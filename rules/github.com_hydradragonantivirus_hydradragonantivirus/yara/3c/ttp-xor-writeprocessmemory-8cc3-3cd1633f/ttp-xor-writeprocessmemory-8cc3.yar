rule TTP_XOR_WriteProcessMemory_8cc3 {
  strings:
    $key_8cc3 = { db b1 [2] e9 93 [2] ef a6 [2] c1 a6 [2] fe ba }

  condition:
    any of them
}