rule TTP_XOR_WriteProcessMemory_bce0 {
  strings:
    $key_bce0 = { eb 92 [2] d9 b0 [2] df 85 [2] f1 85 [2] ce 99 }

  condition:
    any of them
}