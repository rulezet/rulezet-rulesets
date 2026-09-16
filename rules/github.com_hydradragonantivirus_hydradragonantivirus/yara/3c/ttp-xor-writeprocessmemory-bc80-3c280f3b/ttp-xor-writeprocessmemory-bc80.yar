rule TTP_XOR_WriteProcessMemory_bc80 {
  strings:
    $key_bc80 = { eb f2 [2] d9 d0 [2] df e5 [2] f1 e5 [2] ce f9 }

  condition:
    any of them
}