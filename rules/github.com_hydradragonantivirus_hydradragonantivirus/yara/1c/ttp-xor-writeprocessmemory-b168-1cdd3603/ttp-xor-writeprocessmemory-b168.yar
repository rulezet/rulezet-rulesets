rule TTP_XOR_WriteProcessMemory_b168 {
  strings:
    $key_b168 = { e6 1a [2] d4 38 [2] d2 0d [2] fc 0d [2] c3 11 }

  condition:
    any of them
}