rule TTP_XOR_WriteProcessMemory_9696 {
  strings:
    $key_9696 = { c1 e4 [2] f3 c6 [2] f5 f3 [2] db f3 [2] e4 ef }

  condition:
    any of them
}