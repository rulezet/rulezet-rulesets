rule TTP_XOR_WriteProcessMemory_1a66 {
  strings:
    $key_1a66 = { 4d 14 [2] 7f 36 [2] 79 03 [2] 57 03 [2] 68 1f }

  condition:
    any of them
}