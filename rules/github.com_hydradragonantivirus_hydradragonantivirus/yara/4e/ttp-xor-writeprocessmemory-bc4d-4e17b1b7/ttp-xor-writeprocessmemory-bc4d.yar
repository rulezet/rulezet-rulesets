rule TTP_XOR_WriteProcessMemory_bc4d {
  strings:
    $key_bc4d = { eb 3f [2] d9 1d [2] df 28 [2] f1 28 [2] ce 34 }

  condition:
    any of them
}