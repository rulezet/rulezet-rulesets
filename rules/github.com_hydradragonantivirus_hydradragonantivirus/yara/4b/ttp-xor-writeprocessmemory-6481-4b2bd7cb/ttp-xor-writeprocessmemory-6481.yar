rule TTP_XOR_WriteProcessMemory_6481 {
  strings:
    $key_6481 = { 33 f3 [2] 01 d1 [2] 07 e4 [2] 29 e4 [2] 16 f8 }

  condition:
    any of them
}