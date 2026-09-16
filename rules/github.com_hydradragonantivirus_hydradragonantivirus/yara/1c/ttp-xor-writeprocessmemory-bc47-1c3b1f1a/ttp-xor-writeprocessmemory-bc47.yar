rule TTP_XOR_WriteProcessMemory_bc47 {
  strings:
    $key_bc47 = { eb 35 [2] d9 17 [2] df 22 [2] f1 22 [2] ce 3e }

  condition:
    any of them
}