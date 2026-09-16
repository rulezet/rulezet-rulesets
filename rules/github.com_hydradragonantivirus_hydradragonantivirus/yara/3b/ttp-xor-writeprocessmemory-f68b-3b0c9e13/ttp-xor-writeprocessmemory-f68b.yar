rule TTP_XOR_WriteProcessMemory_f68b {
  strings:
    $key_f68b = { a1 f9 [2] 93 db [2] 95 ee [2] bb ee [2] 84 f2 }

  condition:
    any of them
}