rule TTP_XOR_WriteProcessMemory_4416 {
  strings:
    $key_4416 = { 13 64 [2] 21 46 [2] 27 73 [2] 09 73 [2] 36 6f }

  condition:
    any of them
}