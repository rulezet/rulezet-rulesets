rule TTP_XOR_WriteProcessMemory_bc2c {
  strings:
    $key_bc2c = { eb 5e [2] d9 7c [2] df 49 [2] f1 49 [2] ce 55 }

  condition:
    any of them
}