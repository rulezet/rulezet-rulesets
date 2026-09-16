rule TTP_XOR_WriteProcessMemory_1976 {
  strings:
    $key_1976 = { 4e 04 [2] 7c 26 [2] 7a 13 [2] 54 13 [2] 6b 0f }

  condition:
    any of them
}