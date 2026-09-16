rule TTP_XOR_WriteProcessMemory_8987 {
  strings:
    $key_8987 = { de f5 [2] ec d7 [2] ea e2 [2] c4 e2 [2] fb fe }

  condition:
    any of them
}