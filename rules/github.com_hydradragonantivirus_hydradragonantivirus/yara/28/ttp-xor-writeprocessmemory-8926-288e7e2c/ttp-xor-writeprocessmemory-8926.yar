rule TTP_XOR_WriteProcessMemory_8926 {
  strings:
    $key_8926 = { de 54 [2] ec 76 [2] ea 43 [2] c4 43 [2] fb 5f }

  condition:
    any of them
}