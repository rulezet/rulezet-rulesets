rule TTP_XOR_WriteProcessMemory_a0a9 {
  strings:
    $key_a0a9 = { f7 db [2] c5 f9 [2] c3 cc [2] ed cc [2] d2 d0 }

  condition:
    any of them
}