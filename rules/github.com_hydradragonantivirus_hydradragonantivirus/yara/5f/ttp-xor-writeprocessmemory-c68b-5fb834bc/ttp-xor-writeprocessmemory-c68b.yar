rule TTP_XOR_WriteProcessMemory_c68b {
  strings:
    $key_c68b = { 91 f9 [2] a3 db [2] a5 ee [2] 8b ee [2] b4 f2 }

  condition:
    any of them
}