rule TTP_XOR_WriteProcessMemory_8fa5 {
  strings:
    $key_8fa5 = { d8 d7 [2] ea f5 [2] ec c0 [2] c2 c0 [2] fd dc }

  condition:
    any of them
}