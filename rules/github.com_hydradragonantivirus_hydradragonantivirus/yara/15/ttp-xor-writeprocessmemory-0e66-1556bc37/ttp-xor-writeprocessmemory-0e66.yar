rule TTP_XOR_WriteProcessMemory_0e66 {
  strings:
    $key_0e66 = { 59 14 [2] 6b 36 [2] 6d 03 [2] 43 03 [2] 7c 1f }

  condition:
    any of them
}