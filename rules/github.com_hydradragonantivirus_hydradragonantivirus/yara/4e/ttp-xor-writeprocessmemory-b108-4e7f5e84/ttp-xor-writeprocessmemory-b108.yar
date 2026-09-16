rule TTP_XOR_WriteProcessMemory_b108 {
  strings:
    $key_b108 = { e6 7a [2] d4 58 [2] d2 6d [2] fc 6d [2] c3 71 }

  condition:
    any of them
}