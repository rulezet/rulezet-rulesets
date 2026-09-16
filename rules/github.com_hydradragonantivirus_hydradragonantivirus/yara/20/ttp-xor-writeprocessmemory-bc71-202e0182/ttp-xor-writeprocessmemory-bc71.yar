rule TTP_XOR_WriteProcessMemory_bc71 {
  strings:
    $key_bc71 = { eb 03 [2] d9 21 [2] df 14 [2] f1 14 [2] ce 08 }

  condition:
    any of them
}