rule TTP_XOR_WriteProcessMemory_8960 {
  strings:
    $key_8960 = { de 12 [2] ec 30 [2] ea 05 [2] c4 05 [2] fb 19 }

  condition:
    any of them
}