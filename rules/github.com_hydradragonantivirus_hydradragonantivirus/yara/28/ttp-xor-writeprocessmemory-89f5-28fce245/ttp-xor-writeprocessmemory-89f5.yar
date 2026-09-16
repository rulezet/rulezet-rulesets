rule TTP_XOR_WriteProcessMemory_89f5 {
  strings:
    $key_89f5 = { de 87 [2] ec a5 [2] ea 90 [2] c4 90 [2] fb 8c }

  condition:
    any of them
}