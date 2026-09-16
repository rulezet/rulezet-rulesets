rule TTP_XOR_WriteProcessMemory_1e66 {
  strings:
    $key_1e66 = { 49 14 [2] 7b 36 [2] 7d 03 [2] 53 03 [2] 6c 1f }

  condition:
    any of them
}