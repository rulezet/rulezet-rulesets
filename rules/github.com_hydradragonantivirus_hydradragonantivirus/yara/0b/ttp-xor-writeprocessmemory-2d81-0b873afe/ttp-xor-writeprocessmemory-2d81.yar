rule TTP_XOR_WriteProcessMemory_2d81 {
  strings:
    $key_2d81 = { 7a f3 [2] 48 d1 [2] 4e e4 [2] 60 e4 [2] 5f f8 }

  condition:
    any of them
}