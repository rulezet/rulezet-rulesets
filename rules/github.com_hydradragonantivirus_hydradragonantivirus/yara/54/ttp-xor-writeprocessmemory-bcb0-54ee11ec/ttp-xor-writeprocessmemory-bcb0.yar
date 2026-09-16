rule TTP_XOR_WriteProcessMemory_bcb0 {
  strings:
    $key_bcb0 = { eb c2 [2] d9 e0 [2] df d5 [2] f1 d5 [2] ce c9 }

  condition:
    any of them
}