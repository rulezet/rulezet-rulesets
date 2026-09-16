rule TTP_XOR_WriteProcessMemory_bc06 {
  strings:
    $key_bc06 = { eb 74 [2] d9 56 [2] df 63 [2] f1 63 [2] ce 7f }

  condition:
    any of them
}