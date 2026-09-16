rule TTP_XOR_WriteProcessMemory_bc7c {
  strings:
    $key_bc7c = { eb 0e [2] d9 2c [2] df 19 [2] f1 19 [2] ce 05 }

  condition:
    any of them
}