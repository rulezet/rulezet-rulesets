rule TTP_XOR_WriteProcessMemory_9697 {
  strings:
    $key_9697 = { c1 e5 [2] f3 c7 [2] f5 f2 [2] db f2 [2] e4 ee }

  condition:
    any of them
}