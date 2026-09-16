rule TTP_XOR_WriteProcessMemory_bc61 {
  strings:
    $key_bc61 = { eb 13 [2] d9 31 [2] df 04 [2] f1 04 [2] ce 18 }

  condition:
    any of them
}