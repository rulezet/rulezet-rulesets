rule TTP_XOR_WriteProcessMemory_1d76 {
  strings:
    $key_1d76 = { 4a 04 [2] 78 26 [2] 7e 13 [2] 50 13 [2] 6f 0f }

  condition:
    any of them
}