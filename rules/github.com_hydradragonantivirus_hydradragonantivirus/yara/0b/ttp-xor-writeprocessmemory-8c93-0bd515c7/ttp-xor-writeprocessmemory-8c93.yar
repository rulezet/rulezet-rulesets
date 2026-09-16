rule TTP_XOR_WriteProcessMemory_8c93 {
  strings:
    $key_8c93 = { db e1 [2] e9 c3 [2] ef f6 [2] c1 f6 [2] fe ea }

  condition:
    any of them
}