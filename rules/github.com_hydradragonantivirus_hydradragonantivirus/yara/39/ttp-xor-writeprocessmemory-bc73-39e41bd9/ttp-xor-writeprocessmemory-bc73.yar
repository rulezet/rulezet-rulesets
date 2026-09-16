rule TTP_XOR_WriteProcessMemory_bc73 {
  strings:
    $key_bc73 = { eb 01 [2] d9 23 [2] df 16 [2] f1 16 [2] ce 0a }

  condition:
    any of them
}