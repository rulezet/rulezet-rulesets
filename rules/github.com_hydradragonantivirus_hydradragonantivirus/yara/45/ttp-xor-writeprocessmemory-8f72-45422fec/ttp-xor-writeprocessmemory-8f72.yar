rule TTP_XOR_WriteProcessMemory_8f72 {
  strings:
    $key_8f72 = { d8 00 [2] ea 22 [2] ec 17 [2] c2 17 [2] fd 0b }

  condition:
    any of them
}