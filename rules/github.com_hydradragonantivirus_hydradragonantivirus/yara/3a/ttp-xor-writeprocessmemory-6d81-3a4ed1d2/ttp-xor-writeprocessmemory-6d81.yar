rule TTP_XOR_WriteProcessMemory_6d81 {
  strings:
    $key_6d81 = { 3a f3 [2] 08 d1 [2] 0e e4 [2] 20 e4 [2] 1f f8 }

  condition:
    any of them
}