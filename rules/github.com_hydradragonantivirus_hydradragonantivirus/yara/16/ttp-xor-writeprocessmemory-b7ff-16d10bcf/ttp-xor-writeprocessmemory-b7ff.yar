rule TTP_XOR_WriteProcessMemory_b7ff {
  strings:
    $key_b7ff = { e0 8d [2] d2 af [2] d4 9a [2] fa 9a [2] c5 86 }

  condition:
    any of them
}