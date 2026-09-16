rule TTP_XOR_WriteProcessMemory_8ca2 {
  strings:
    $key_8ca2 = { db d0 [2] e9 f2 [2] ef c7 [2] c1 c7 [2] fe db }

  condition:
    any of them
}