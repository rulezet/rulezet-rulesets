rule TTP_XOR_WriteProcessMemory_8fa7 {
  strings:
    $key_8fa7 = { d8 d5 [2] ea f7 [2] ec c2 [2] c2 c2 [2] fd de }

  condition:
    any of them
}