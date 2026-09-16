rule TTP_XOR_WriteProcessMemory_8fb1 {
  strings:
    $key_8fb1 = { d8 c3 [2] ea e1 [2] ec d4 [2] c2 d4 [2] fd c8 }

  condition:
    any of them
}