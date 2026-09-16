rule TTP_XOR_WriteProcessMemory_d68b {
  strings:
    $key_d68b = { 81 f9 [2] b3 db [2] b5 ee [2] 9b ee [2] a4 f2 }

  condition:
    any of them
}