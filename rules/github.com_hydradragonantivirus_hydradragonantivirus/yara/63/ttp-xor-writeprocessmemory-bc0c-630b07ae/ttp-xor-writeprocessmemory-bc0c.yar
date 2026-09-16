rule TTP_XOR_WriteProcessMemory_bc0c {
  strings:
    $key_bc0c = { eb 7e [2] d9 5c [2] df 69 [2] f1 69 [2] ce 75 }

  condition:
    any of them
}