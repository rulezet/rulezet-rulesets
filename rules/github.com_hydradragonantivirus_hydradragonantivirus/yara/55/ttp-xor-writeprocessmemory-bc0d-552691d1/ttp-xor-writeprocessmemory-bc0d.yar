rule TTP_XOR_WriteProcessMemory_bc0d {
  strings:
    $key_bc0d = { eb 7f [2] d9 5d [2] df 68 [2] f1 68 [2] ce 74 }

  condition:
    any of them
}