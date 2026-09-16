rule TTP_XOR_WriteProcessMemory_2c51 {
  strings:
    $key_2c51 = { 7b 23 [2] 49 01 [2] 4f 34 [2] 61 34 [2] 5e 28 }

  condition:
    any of them
}