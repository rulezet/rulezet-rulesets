rule TTP_XOR_WriteProcessMemory_8c94 {
  strings:
    $key_8c94 = { db e6 [2] e9 c4 [2] ef f1 [2] c1 f1 [2] fe ed }

  condition:
    any of them
}