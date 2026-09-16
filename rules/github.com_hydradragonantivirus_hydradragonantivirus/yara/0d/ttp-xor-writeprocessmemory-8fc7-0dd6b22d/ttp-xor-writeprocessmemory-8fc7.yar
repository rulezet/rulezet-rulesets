rule TTP_XOR_WriteProcessMemory_8fc7 {
  strings:
    $key_8fc7 = { d8 b5 [2] ea 97 [2] ec a2 [2] c2 a2 [2] fd be }

  condition:
    any of them
}