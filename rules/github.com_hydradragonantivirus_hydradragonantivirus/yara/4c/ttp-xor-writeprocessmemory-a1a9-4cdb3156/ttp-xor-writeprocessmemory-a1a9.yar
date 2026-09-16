rule TTP_XOR_WriteProcessMemory_a1a9 {
  strings:
    $key_a1a9 = { f6 db [2] c4 f9 [2] c2 cc [2] ec cc [2] d3 d0 }

  condition:
    any of them
}