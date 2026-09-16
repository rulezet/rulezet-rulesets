rule TTP_XOR_WriteProcessMemory_b50f {
  strings:
    $key_b50f = { e2 7d [2] d0 5f [2] d6 6a [2] f8 6a [2] c7 76 }

  condition:
    any of them
}