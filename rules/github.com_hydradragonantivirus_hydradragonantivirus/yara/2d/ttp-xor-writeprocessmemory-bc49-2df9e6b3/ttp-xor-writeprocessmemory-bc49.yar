rule TTP_XOR_WriteProcessMemory_bc49 {
  strings:
    $key_bc49 = { eb 3b [2] d9 19 [2] df 2c [2] f1 2c [2] ce 30 }

  condition:
    any of them
}