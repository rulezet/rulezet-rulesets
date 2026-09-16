rule TTP_XOR_WriteProcessMemory_bcf1 {
  strings:
    $key_bcf1 = { eb 83 [2] d9 a1 [2] df 94 [2] f1 94 [2] ce 88 }

  condition:
    any of them
}