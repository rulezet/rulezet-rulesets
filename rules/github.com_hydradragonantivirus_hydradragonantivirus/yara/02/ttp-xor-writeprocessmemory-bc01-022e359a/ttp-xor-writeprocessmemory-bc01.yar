rule TTP_XOR_WriteProcessMemory_bc01 {
  strings:
    $key_bc01 = { eb 73 [2] d9 51 [2] df 64 [2] f1 64 [2] ce 78 }

  condition:
    any of them
}