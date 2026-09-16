rule TTP_XOR_WriteProcessMemory_bc00 {
  strings:
    $key_bc00 = { eb 72 [2] d9 50 [2] df 65 [2] f1 65 [2] ce 79 }

  condition:
    any of them
}