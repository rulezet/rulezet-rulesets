rule TTP_XOR_WriteProcessMemory_0f76 {
  strings:
    $key_0f76 = { 58 04 [2] 6a 26 [2] 6c 13 [2] 42 13 [2] 7d 0f }

  condition:
    any of them
}