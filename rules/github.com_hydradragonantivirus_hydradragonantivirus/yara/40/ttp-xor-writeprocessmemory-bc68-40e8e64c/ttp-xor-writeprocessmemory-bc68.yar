rule TTP_XOR_WriteProcessMemory_bc68 {
  strings:
    $key_bc68 = { eb 1a [2] d9 38 [2] df 0d [2] f1 0d [2] ce 11 }

  condition:
    any of them
}