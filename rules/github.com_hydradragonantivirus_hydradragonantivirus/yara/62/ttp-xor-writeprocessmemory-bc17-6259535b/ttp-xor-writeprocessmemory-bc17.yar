rule TTP_XOR_WriteProcessMemory_bc17 {
  strings:
    $key_bc17 = { eb 65 [2] d9 47 [2] df 72 [2] f1 72 [2] ce 6e }

  condition:
    any of them
}