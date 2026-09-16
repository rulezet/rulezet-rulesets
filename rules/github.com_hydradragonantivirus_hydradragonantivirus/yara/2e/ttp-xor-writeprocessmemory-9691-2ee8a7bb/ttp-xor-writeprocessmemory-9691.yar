rule TTP_XOR_WriteProcessMemory_9691 {
  strings:
    $key_9691 = { c1 e3 [2] f3 c1 [2] f5 f4 [2] db f4 [2] e4 e8 }

  condition:
    any of them
}