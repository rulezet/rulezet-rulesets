rule TTP_XOR_WriteProcessMemory_bcd0 {
  strings:
    $key_bcd0 = { eb a2 [2] d9 80 [2] df b5 [2] f1 b5 [2] ce a9 }

  condition:
    any of them
}