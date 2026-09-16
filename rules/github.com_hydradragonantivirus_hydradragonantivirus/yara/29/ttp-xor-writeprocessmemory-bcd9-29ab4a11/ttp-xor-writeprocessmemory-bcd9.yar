rule TTP_XOR_WriteProcessMemory_bcd9 {
  strings:
    $key_bcd9 = { eb ab [2] d9 89 [2] df bc [2] f1 bc [2] ce a0 }

  condition:
    any of them
}