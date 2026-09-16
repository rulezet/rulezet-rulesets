rule TTP_XOR_WriteProcessMemory_2c02 {
  strings:
    $key_2c02 = { 7b 70 [2] 49 52 [2] 4f 67 [2] 61 67 [2] 5e 7b }

  condition:
    any of them
}