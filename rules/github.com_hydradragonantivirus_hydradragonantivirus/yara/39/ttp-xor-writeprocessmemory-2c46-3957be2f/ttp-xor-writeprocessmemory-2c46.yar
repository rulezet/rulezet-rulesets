rule TTP_XOR_WriteProcessMemory_2c46 {
  strings:
    $key_2c46 = { 7b 34 [2] 49 16 [2] 4f 23 [2] 61 23 [2] 5e 3f }

  condition:
    any of them
}