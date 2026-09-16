rule TTP_XOR_WriteProcessMemory_1c81 {
  strings:
    $key_1c81 = { 4b f3 [2] 79 d1 [2] 7f e4 [2] 51 e4 [2] 6e f8 }

  condition:
    any of them
}