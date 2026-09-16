rule TTP_XOR_WriteProcessMemory_bc7b {
  strings:
    $key_bc7b = { eb 09 [2] d9 2b [2] df 1e [2] f1 1e [2] ce 02 }

  condition:
    any of them
}