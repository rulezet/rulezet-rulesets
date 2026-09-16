rule TTP_XOR_WriteProcessMemory_3c66 {
  strings:
    $key_3c66 = { 6b 14 [2] 59 36 [2] 5f 03 [2] 71 03 [2] 4e 1f }

  condition:
    any of them
}