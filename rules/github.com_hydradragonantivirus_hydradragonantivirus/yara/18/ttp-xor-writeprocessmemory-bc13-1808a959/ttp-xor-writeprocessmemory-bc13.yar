rule TTP_XOR_WriteProcessMemory_bc13 {
  strings:
    $key_bc13 = { eb 61 [2] d9 43 [2] df 76 [2] f1 76 [2] ce 6a }

  condition:
    any of them
}