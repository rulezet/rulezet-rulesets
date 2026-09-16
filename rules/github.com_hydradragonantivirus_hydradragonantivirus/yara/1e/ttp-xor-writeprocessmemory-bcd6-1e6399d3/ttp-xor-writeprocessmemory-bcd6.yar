rule TTP_XOR_WriteProcessMemory_bcd6 {
  strings:
    $key_bcd6 = { eb a4 [2] d9 86 [2] df b3 [2] f1 b3 [2] ce af }

  condition:
    any of them
}