rule TTP_XOR_WriteProcessMemory_c28b {
  strings:
    $key_c28b = { 95 f9 [2] a7 db [2] a1 ee [2] 8f ee [2] b0 f2 }

  condition:
    any of them
}