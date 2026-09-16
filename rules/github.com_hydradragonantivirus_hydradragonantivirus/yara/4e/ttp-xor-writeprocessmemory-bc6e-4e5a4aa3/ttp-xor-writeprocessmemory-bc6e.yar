rule TTP_XOR_WriteProcessMemory_bc6e {
  strings:
    $key_bc6e = { eb 1c [2] d9 3e [2] df 0b [2] f1 0b [2] ce 17 }

  condition:
    any of them
}