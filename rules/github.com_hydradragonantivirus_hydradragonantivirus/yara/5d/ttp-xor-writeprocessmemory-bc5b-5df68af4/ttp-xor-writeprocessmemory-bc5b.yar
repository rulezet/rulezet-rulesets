rule TTP_XOR_WriteProcessMemory_bc5b {
  strings:
    $key_bc5b = { eb 29 [2] d9 0b [2] df 3e [2] f1 3e [2] ce 22 }

  condition:
    any of them
}