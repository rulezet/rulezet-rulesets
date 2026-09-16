rule TTP_XOR_WriteProcessMemory_b5ff {
  strings:
    $key_b5ff = { e2 8d [2] d0 af [2] d6 9a [2] f8 9a [2] c7 86 }

  condition:
    any of them
}