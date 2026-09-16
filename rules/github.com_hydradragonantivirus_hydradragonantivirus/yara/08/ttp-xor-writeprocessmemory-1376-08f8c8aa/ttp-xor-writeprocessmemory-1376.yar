rule TTP_XOR_WriteProcessMemory_1376 {
  strings:
    $key_1376 = { 44 04 [2] 76 26 [2] 70 13 [2] 5e 13 [2] 61 0f }

  condition:
    any of them
}