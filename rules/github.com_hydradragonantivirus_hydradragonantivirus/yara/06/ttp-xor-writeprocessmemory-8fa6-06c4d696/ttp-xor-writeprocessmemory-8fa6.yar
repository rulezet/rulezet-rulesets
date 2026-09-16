rule TTP_XOR_WriteProcessMemory_8fa6 {
  strings:
    $key_8fa6 = { d8 d4 [2] ea f6 [2] ec c3 [2] c2 c3 [2] fd df }

  condition:
    any of them
}