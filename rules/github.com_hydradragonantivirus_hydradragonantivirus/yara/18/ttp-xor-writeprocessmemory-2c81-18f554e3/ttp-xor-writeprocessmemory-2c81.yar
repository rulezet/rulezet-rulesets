rule TTP_XOR_WriteProcessMemory_2c81 {
  strings:
    $key_2c81 = { 7b f3 [2] 49 d1 [2] 4f e4 [2] 61 e4 [2] 5e f8 }

  condition:
    any of them
}