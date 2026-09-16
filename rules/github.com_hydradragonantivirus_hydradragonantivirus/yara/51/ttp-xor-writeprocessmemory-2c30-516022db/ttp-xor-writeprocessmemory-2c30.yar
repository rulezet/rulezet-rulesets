rule TTP_XOR_WriteProcessMemory_2c30 {
  strings:
    $key_2c30 = { 7b 42 [2] 49 60 [2] 4f 55 [2] 61 55 [2] 5e 49 }

  condition:
    any of them
}