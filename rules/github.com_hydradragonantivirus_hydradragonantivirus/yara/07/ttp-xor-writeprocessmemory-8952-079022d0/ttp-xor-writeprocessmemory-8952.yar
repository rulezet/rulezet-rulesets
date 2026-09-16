rule TTP_XOR_WriteProcessMemory_8952 {
  strings:
    $key_8952 = { de 20 [2] ec 02 [2] ea 37 [2] c4 37 [2] fb 2b }

  condition:
    any of them
}