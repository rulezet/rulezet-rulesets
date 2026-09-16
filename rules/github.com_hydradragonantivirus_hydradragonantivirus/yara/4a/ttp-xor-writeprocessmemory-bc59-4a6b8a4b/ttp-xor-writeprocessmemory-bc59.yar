rule TTP_XOR_WriteProcessMemory_bc59 {
  strings:
    $key_bc59 = { eb 2b [2] d9 09 [2] df 3c [2] f1 3c [2] ce 20 }

  condition:
    any of them
}