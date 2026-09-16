rule TTP_XOR_WriteProcessMemory_1d16 {
  strings:
    $key_1d16 = { 4a 64 [2] 78 46 [2] 7e 73 [2] 50 73 [2] 6f 6f }

  condition:
    any of them
}