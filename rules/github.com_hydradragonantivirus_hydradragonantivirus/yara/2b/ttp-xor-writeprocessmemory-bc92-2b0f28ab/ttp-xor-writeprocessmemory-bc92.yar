rule TTP_XOR_WriteProcessMemory_bc92 {
  strings:
    $key_bc92 = { eb e0 [2] d9 c2 [2] df f7 [2] f1 f7 [2] ce eb }

  condition:
    any of them
}