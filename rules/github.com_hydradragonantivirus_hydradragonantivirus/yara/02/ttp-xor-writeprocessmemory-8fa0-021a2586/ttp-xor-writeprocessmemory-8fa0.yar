rule TTP_XOR_WriteProcessMemory_8fa0 {
  strings:
    $key_8fa0 = { d8 d2 [2] ea f0 [2] ec c5 [2] c2 c5 [2] fd d9 }

  condition:
    any of them
}