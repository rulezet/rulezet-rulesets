rule TTP_XOR_WriteProcessMemory_e446 {
  strings:
    $key_e446 = { b3 34 [2] 81 16 [2] 87 23 [2] a9 23 [2] 96 3f }

  condition:
    any of them
}