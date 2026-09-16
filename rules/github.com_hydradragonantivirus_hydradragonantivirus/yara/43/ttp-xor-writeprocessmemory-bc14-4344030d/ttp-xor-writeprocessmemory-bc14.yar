rule TTP_XOR_WriteProcessMemory_bc14 {
  strings:
    $key_bc14 = { eb 66 [2] d9 44 [2] df 71 [2] f1 71 [2] ce 6d }

  condition:
    any of them
}