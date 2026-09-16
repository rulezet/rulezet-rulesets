rule TTP_XOR_WriteProcessMemory_1076 {
  strings:
    $key_1076 = { 47 04 [2] 75 26 [2] 73 13 [2] 5d 13 [2] 62 0f }

  condition:
    any of them
}