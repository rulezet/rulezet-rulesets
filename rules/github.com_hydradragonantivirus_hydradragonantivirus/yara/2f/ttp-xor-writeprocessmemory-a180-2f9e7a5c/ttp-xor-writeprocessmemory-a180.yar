rule TTP_XOR_WriteProcessMemory_a180 {
  strings:
    $key_a180 = { f6 f2 [2] c4 d0 [2] c2 e5 [2] ec e5 [2] d3 f9 }

  condition:
    any of them
}