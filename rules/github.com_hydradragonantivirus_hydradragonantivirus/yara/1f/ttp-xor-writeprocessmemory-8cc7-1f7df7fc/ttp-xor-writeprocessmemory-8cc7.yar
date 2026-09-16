rule TTP_XOR_WriteProcessMemory_8cc7 {
  strings:
    $key_8cc7 = { db b5 [2] e9 97 [2] ef a2 [2] c1 a2 [2] fe be }

  condition:
    any of them
}