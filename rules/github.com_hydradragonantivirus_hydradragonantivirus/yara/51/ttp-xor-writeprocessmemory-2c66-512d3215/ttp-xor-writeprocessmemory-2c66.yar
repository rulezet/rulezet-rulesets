rule TTP_XOR_WriteProcessMemory_2c66 {
  strings:
    $key_2c66 = { 7b 14 [2] 49 36 [2] 4f 03 [2] 61 03 [2] 5e 1f }

  condition:
    any of them
}