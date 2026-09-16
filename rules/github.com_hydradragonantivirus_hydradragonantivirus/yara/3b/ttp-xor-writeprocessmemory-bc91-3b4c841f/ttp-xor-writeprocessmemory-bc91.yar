rule TTP_XOR_WriteProcessMemory_bc91 {
  strings:
    $key_bc91 = { eb e3 [2] d9 c1 [2] df f4 [2] f1 f4 [2] ce e8 }

  condition:
    any of them
}