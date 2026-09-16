rule TTP_XOR_WriteProcessMemory_89b0 {
  strings:
    $key_89b0 = { de c2 [2] ec e0 [2] ea d5 [2] c4 d5 [2] fb c9 }

  condition:
    any of them
}