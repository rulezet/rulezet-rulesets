rule TTP_XOR_WriteProcessMemory_71f7 {
  strings:
    $key_71f7 = { 26 85 [2] 14 a7 [2] 12 92 [2] 3c 92 [2] 03 8e }

  condition:
    any of them
}