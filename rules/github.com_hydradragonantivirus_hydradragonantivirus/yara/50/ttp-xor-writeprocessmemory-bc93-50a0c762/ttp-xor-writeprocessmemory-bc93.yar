rule TTP_XOR_WriteProcessMemory_bc93 {
  strings:
    $key_bc93 = { eb e1 [2] d9 c3 [2] df f6 [2] f1 f6 [2] ce ea }

  condition:
    any of them
}