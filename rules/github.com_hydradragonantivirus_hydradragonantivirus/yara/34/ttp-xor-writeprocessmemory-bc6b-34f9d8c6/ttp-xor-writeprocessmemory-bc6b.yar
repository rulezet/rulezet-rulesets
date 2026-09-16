rule TTP_XOR_WriteProcessMemory_bc6b {
  strings:
    $key_bc6b = { eb 19 [2] d9 3b [2] df 0e [2] f1 0e [2] ce 12 }

  condition:
    any of them
}