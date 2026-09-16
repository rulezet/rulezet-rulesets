rule TTP_XOR_WriteProcessMemory_2c8c {
  strings:
    $key_2c8c = { 7b fe [2] 49 dc [2] 4f e9 [2] 61 e9 [2] 5e f5 }

  condition:
    any of them
}