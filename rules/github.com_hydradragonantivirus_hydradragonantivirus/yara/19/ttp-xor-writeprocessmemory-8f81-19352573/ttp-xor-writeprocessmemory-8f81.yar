rule TTP_XOR_WriteProcessMemory_8f81 {
  strings:
    $key_8f81 = { d8 f3 [2] ea d1 [2] ec e4 [2] c2 e4 [2] fd f8 }

  condition:
    any of them
}