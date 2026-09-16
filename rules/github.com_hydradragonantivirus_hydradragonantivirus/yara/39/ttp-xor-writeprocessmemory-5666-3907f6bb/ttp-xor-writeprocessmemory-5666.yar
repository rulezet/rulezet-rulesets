rule TTP_XOR_WriteProcessMemory_5666 {
  strings:
    $key_5666 = { 01 14 [2] 33 36 [2] 35 03 [2] 1b 03 [2] 24 1f }

  condition:
    any of them
}