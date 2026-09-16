rule TTP_XOR_WriteProcessMemory_92b3 {
  strings:
    $key_92b3 = { c5 c1 [2] f7 e3 [2] f1 d6 [2] df d6 [2] e0 ca }

  condition:
    any of them
}