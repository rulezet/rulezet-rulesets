rule TTP_XOR_WriteProcessMemory_4076 {
  strings:
    $key_4076 = { 17 04 [2] 25 26 [2] 23 13 [2] 0d 13 [2] 32 0f }

  condition:
    any of them
}