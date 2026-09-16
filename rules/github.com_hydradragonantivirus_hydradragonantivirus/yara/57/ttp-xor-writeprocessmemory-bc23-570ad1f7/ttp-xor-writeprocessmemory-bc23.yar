rule TTP_XOR_WriteProcessMemory_bc23 {
  strings:
    $key_bc23 = { eb 51 [2] d9 73 [2] df 46 [2] f1 46 [2] ce 5a }

  condition:
    any of them
}