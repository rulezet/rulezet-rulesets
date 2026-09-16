rule TTP_XOR_WriteProcessMemory_89f1 {
  strings:
    $key_89f1 = { de 83 [2] ec a1 [2] ea 94 [2] c4 94 [2] fb 88 }

  condition:
    any of them
}