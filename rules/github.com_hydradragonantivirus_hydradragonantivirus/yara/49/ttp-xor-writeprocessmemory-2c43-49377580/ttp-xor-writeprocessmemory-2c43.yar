rule TTP_XOR_WriteProcessMemory_2c43 {
  strings:
    $key_2c43 = { 7b 31 [2] 49 13 [2] 4f 26 [2] 61 26 [2] 5e 3a }

  condition:
    any of them
}