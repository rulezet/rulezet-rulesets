rule TTP_XOR_WriteProcessMemory_89f0 {
  strings:
    $key_89f0 = { de 82 [2] ec a0 [2] ea 95 [2] c4 95 [2] fb 89 }

  condition:
    any of them
}