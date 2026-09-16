rule TTP_XOR_WriteProcessMemory_bc5c {
  strings:
    $key_bc5c = { eb 2e [2] d9 0c [2] df 39 [2] f1 39 [2] ce 25 }

  condition:
    any of them
}