rule TTP_XOR_WriteProcessMemory_92d0 {
  strings:
    $key_92d0 = { c5 a2 [2] f7 80 [2] f1 b5 [2] df b5 [2] e0 a9 }

  condition:
    any of them
}