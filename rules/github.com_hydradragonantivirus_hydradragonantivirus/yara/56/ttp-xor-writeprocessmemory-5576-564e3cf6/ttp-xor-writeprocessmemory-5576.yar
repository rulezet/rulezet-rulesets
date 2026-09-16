rule TTP_XOR_WriteProcessMemory_5576 {
  strings:
    $key_5576 = { 02 04 [2] 30 26 [2] 36 13 [2] 18 13 [2] 27 0f }

  condition:
    any of them
}