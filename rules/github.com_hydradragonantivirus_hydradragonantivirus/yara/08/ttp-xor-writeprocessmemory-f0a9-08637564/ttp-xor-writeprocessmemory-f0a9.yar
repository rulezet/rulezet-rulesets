rule TTP_XOR_WriteProcessMemory_f0a9 {
  strings:
    $key_f0a9 = { a7 db [2] 95 f9 [2] 93 cc [2] bd cc [2] 82 d0 }

  condition:
    any of them
}