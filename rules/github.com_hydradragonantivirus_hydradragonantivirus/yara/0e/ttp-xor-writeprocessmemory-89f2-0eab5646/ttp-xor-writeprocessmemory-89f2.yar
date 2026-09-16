rule TTP_XOR_WriteProcessMemory_89f2 {
  strings:
    $key_89f2 = { de 80 [2] ec a2 [2] ea 97 [2] c4 97 [2] fb 8b }

  condition:
    any of them
}