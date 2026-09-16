rule TTP_XOR_WriteProcessMemory_5376 {
  strings:
    $key_5376 = { 04 04 [2] 36 26 [2] 30 13 [2] 1e 13 [2] 21 0f }

  condition:
    any of them
}