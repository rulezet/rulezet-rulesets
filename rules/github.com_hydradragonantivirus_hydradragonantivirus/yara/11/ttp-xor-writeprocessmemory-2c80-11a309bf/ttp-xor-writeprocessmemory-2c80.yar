rule TTP_XOR_WriteProcessMemory_2c80 {
  strings:
    $key_2c80 = { 7b f2 [2] 49 d0 [2] 4f e5 [2] 61 e5 [2] 5e f9 }

  condition:
    any of them
}