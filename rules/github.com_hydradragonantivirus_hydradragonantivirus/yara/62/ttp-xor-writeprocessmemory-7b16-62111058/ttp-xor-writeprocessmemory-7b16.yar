rule TTP_XOR_WriteProcessMemory_7b16 {
  strings:
    $key_7b16 = { 2c 64 [2] 1e 46 [2] 18 73 [2] 36 73 [2] 09 6f }

  condition:
    any of them
}