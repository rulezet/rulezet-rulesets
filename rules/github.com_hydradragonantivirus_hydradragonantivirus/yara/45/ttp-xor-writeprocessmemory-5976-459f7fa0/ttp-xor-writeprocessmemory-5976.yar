rule TTP_XOR_WriteProcessMemory_5976 {
  strings:
    $key_5976 = { 0e 04 [2] 3c 26 [2] 3a 13 [2] 14 13 [2] 2b 0f }

  condition:
    any of them
}