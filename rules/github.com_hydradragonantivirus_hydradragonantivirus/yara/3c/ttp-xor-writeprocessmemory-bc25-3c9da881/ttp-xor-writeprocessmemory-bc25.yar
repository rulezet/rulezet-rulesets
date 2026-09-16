rule TTP_XOR_WriteProcessMemory_bc25 {
  strings:
    $key_bc25 = { eb 57 [2] d9 75 [2] df 40 [2] f1 40 [2] ce 5c }

  condition:
    any of them
}