rule TTP_XOR_WriteProcessMemory_bc67 {
  strings:
    $key_bc67 = { eb 15 [2] d9 37 [2] df 02 [2] f1 02 [2] ce 1e }

  condition:
    any of them
}