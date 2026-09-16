rule TTP_XOR_WriteProcessMemory_8fc4 {
  strings:
    $key_8fc4 = { d8 b6 [2] ea 94 [2] ec a1 [2] c2 a1 [2] fd bd }

  condition:
    any of them
}