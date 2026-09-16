rule TTP_XOR_WriteProcessMemory_5416 {
  strings:
    $key_5416 = { 03 64 [2] 31 46 [2] 37 73 [2] 19 73 [2] 26 6f }

  condition:
    any of them
}