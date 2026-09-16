rule TTP_XOR_WriteProcessMemory_bc16 {
  strings:
    $key_bc16 = { eb 64 [2] d9 46 [2] df 73 [2] f1 73 [2] ce 6f }

  condition:
    any of them
}