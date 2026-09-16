rule TTP_XOR_WriteProcessMemory_8967 {
  strings:
    $key_8967 = { de 15 [2] ec 37 [2] ea 02 [2] c4 02 [2] fb 1e }

  condition:
    any of them
}