rule TTP_XOR_WriteProcessMemory_1876 {
  strings:
    $key_1876 = { 4f 04 [2] 7d 26 [2] 7b 13 [2] 55 13 [2] 6a 0f }

  condition:
    any of them
}