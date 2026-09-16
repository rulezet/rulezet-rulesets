rule TTP_XOR_WriteProcessMemory_8fc0 {
  strings:
    $key_8fc0 = { d8 b2 [2] ea 90 [2] ec a5 [2] c2 a5 [2] fd b9 }

  condition:
    any of them
}