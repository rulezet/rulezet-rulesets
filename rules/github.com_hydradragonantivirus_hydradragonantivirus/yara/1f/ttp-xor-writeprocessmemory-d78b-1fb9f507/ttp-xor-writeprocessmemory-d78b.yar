rule TTP_XOR_WriteProcessMemory_d78b {
  strings:
    $key_d78b = { 80 f9 [2] b2 db [2] b4 ee [2] 9a ee [2] a5 f2 }

  condition:
    any of them
}