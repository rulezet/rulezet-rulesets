rule TTP_XOR_WriteProcessMemory_8973 {
  strings:
    $key_8973 = { de 01 [2] ec 23 [2] ea 16 [2] c4 16 [2] fb 0a }

  condition:
    any of them
}