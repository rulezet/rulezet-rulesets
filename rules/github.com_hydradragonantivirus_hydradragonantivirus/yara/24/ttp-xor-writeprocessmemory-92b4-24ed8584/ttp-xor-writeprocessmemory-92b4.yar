rule TTP_XOR_WriteProcessMemory_92b4 {
  strings:
    $key_92b4 = { c5 c6 [2] f7 e4 [2] f1 d1 [2] df d1 [2] e0 cd }

  condition:
    any of them
}