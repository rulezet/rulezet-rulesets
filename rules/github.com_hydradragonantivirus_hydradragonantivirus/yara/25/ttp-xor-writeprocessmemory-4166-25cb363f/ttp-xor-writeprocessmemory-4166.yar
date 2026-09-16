rule TTP_XOR_WriteProcessMemory_4166 {
  strings:
    $key_4166 = { 16 14 [2] 24 36 [2] 22 03 [2] 0c 03 [2] 33 1f }

  condition:
    any of them
}