rule TTP_XOR_WriteProcessMemory_bc50 {
  strings:
    $key_bc50 = { eb 22 [2] d9 00 [2] df 35 [2] f1 35 [2] ce 29 }

  condition:
    any of them
}