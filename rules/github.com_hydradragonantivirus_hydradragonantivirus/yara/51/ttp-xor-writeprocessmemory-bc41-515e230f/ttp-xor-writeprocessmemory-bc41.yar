rule TTP_XOR_WriteProcessMemory_bc41 {
  strings:
    $key_bc41 = { eb 33 [2] d9 11 [2] df 24 [2] f1 24 [2] ce 38 }

  condition:
    any of them
}