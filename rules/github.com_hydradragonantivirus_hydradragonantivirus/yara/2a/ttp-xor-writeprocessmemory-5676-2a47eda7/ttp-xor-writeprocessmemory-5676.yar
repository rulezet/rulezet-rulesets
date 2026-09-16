rule TTP_XOR_WriteProcessMemory_5676 {
  strings:
    $key_5676 = { 01 04 [2] 33 26 [2] 35 13 [2] 1b 13 [2] 24 0f }

  condition:
    any of them
}