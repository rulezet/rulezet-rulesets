rule TTP_XOR_WriteProcessMemory_8fb2 {
  strings:
    $key_8fb2 = { d8 c0 [2] ea e2 [2] ec d7 [2] c2 d7 [2] fd cb }

  condition:
    any of them
}