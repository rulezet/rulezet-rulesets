rule TTP_XOR_WriteProcessMemory_d28b {
  strings:
    $key_d28b = { 85 f9 [2] b7 db [2] b1 ee [2] 9f ee [2] a0 f2 }

  condition:
    any of them
}