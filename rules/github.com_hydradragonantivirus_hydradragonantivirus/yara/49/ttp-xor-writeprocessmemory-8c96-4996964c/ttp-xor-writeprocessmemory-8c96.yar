rule TTP_XOR_WriteProcessMemory_8c96 {
  strings:
    $key_8c96 = { db e4 [2] e9 c6 [2] ef f3 [2] c1 f3 [2] fe ef }

  condition:
    any of them
}