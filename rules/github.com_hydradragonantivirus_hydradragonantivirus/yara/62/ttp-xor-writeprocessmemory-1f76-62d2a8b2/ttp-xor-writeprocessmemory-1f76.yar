rule TTP_XOR_WriteProcessMemory_1f76 {
  strings:
    $key_1f76 = { 48 04 [2] 7a 26 [2] 7c 13 [2] 52 13 [2] 6d 0f }

  condition:
    any of them
}