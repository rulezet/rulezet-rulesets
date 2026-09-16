rule TTP_XOR_WriteProcessMemory_bc35 {
  strings:
    $key_bc35 = { eb 47 [2] d9 65 [2] df 50 [2] f1 50 [2] ce 4c }

  condition:
    any of them
}