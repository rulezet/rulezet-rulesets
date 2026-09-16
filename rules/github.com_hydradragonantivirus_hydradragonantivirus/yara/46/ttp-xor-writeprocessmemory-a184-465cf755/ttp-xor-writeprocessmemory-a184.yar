rule TTP_XOR_WriteProcessMemory_a184 {
  strings:
    $key_a184 = { f6 f6 [2] c4 d4 [2] c2 e1 [2] ec e1 [2] d3 fd }

  condition:
    any of them
}