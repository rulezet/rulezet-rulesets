rule TTP_XOR_WriteProcessMemory_2c72 {
  strings:
    $key_2c72 = { 7b 00 [2] 49 22 [2] 4f 17 [2] 61 17 [2] 5e 0b }

  condition:
    any of them
}