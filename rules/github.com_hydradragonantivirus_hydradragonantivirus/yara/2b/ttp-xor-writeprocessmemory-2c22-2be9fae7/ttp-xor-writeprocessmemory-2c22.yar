rule TTP_XOR_WriteProcessMemory_2c22 {
  strings:
    $key_2c22 = { 7b 50 [2] 49 72 [2] 4f 47 [2] 61 47 [2] 5e 5b }

  condition:
    any of them
}