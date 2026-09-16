rule TTP_XOR_WriteProcessMemory_8981 {
  strings:
    $key_8981 = { de f3 [2] ec d1 [2] ea e4 [2] c4 e4 [2] fb f8 }

  condition:
    any of them
}