rule TTP_XOR_WriteProcessMemory_8fa1 {
  strings:
    $key_8fa1 = { d8 d3 [2] ea f1 [2] ec c4 [2] c2 c4 [2] fd d8 }

  condition:
    any of them
}