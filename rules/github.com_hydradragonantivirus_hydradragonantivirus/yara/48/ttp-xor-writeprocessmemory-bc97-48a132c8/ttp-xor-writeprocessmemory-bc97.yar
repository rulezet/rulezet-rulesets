rule TTP_XOR_WriteProcessMemory_bc97 {
  strings:
    $key_bc97 = { eb e5 [2] d9 c7 [2] df f2 [2] f1 f2 [2] ce ee }

  condition:
    any of them
}