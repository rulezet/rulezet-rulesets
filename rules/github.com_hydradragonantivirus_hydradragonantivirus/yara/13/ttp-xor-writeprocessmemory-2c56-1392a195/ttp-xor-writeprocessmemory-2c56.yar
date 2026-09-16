rule TTP_XOR_WriteProcessMemory_2c56 {
  strings:
    $key_2c56 = { 7b 24 [2] 49 06 [2] 4f 33 [2] 61 33 [2] 5e 2f }

  condition:
    any of them
}