rule TTP_XOR_WriteProcessMemory_bc1d {
  strings:
    $key_bc1d = { eb 6f [2] d9 4d [2] df 78 [2] f1 78 [2] ce 64 }

  condition:
    any of them
}