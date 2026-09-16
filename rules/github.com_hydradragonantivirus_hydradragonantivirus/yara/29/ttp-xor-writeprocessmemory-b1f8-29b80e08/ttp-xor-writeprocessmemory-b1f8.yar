rule TTP_XOR_WriteProcessMemory_b1f8 {
  strings:
    $key_b1f8 = { e6 8a [2] d4 a8 [2] d2 9d [2] fc 9d [2] c3 81 }

  condition:
    any of them
}