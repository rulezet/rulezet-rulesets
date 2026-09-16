rule TTP_XOR_WriteProcessMemory_bcd2 {
  strings:
    $key_bcd2 = { eb a0 [2] d9 82 [2] df b7 [2] f1 b7 [2] ce ab }

  condition:
    any of them
}