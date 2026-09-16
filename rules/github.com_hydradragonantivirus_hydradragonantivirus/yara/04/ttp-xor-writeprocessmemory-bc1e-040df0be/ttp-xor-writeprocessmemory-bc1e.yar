rule TTP_XOR_WriteProcessMemory_bc1e {
  strings:
    $key_bc1e = { eb 6c [2] d9 4e [2] df 7b [2] f1 7b [2] ce 67 }

  condition:
    any of them
}