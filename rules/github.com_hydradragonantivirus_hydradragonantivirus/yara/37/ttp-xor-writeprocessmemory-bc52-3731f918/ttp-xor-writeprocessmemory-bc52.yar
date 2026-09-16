rule TTP_XOR_WriteProcessMemory_bc52 {
  strings:
    $key_bc52 = { eb 20 [2] d9 02 [2] df 37 [2] f1 37 [2] ce 2b }

  condition:
    any of them
}