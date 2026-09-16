rule TTP_XOR_WriteProcessMemory_0c81 {
  strings:
    $key_0c81 = { 5b f3 [2] 69 d1 [2] 6f e4 [2] 41 e4 [2] 7e f8 }

  condition:
    any of them
}