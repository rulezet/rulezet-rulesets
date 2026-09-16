rule TTP_XOR_WriteProcessMemory_bc3b {
  strings:
    $key_bc3b = { eb 49 [2] d9 6b [2] df 5e [2] f1 5e [2] ce 42 }

  condition:
    any of them
}