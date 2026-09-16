rule TTP_XOR_WriteProcessMemory_bcd7 {
  strings:
    $key_bcd7 = { eb a5 [2] d9 87 [2] df b2 [2] f1 b2 [2] ce ae }

  condition:
    any of them
}