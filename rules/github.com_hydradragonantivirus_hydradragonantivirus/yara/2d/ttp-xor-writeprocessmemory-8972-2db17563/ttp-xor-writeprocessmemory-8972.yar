rule TTP_XOR_WriteProcessMemory_8972 {
  strings:
    $key_8972 = { de 00 [2] ec 22 [2] ea 17 [2] c4 17 [2] fb 0b }

  condition:
    any of them
}