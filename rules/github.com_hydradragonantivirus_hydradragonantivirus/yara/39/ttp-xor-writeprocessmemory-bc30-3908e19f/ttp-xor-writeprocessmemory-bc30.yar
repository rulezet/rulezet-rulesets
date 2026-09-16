rule TTP_XOR_WriteProcessMemory_bc30 {
  strings:
    $key_bc30 = { eb 42 [2] d9 60 [2] df 55 [2] f1 55 [2] ce 49 }

  condition:
    any of them
}