rule TTP_XOR_WriteProcessMemory_bcd4 {
  strings:
    $key_bcd4 = { eb a6 [2] d9 84 [2] df b1 [2] f1 b1 [2] ce ad }

  condition:
    any of them
}