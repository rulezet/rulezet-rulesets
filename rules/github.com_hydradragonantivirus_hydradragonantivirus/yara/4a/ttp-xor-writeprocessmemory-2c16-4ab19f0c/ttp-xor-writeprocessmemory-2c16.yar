rule TTP_XOR_WriteProcessMemory_2c16 {
  strings:
    $key_2c16 = { 7b 64 [2] 49 46 [2] 4f 73 [2] 61 73 [2] 5e 6f }

  condition:
    any of them
}