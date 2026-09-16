rule TTP_XOR_WriteProcessMemory_8391 {
  strings:
    $key_8391 = { d4 e3 [2] e6 c1 [2] e0 f4 [2] ce f4 [2] f1 e8 }

  condition:
    any of them
}