rule TTP_XOR_WriteProcessMemory_a181 {
  strings:
    $key_a181 = { f6 f3 [2] c4 d1 [2] c2 e4 [2] ec e4 [2] d3 f8 }

  condition:
    any of them
}