rule TTP_XOR_WriteProcessMemory_92d5 {
  strings:
    $key_92d5 = { c5 a7 [2] f7 85 [2] f1 b0 [2] df b0 [2] e0 ac }

  condition:
    any of them
}