rule TTP_XOR_WriteProcessMemory_1a76 {
  strings:
    $key_1a76 = { 4d 04 [2] 7f 26 [2] 79 13 [2] 57 13 [2] 68 0f }

  condition:
    any of them
}