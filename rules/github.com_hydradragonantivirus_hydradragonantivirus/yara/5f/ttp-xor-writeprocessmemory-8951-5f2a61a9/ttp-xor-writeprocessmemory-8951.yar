rule TTP_XOR_WriteProcessMemory_8951 {
  strings:
    $key_8951 = { de 23 [2] ec 01 [2] ea 34 [2] c4 34 [2] fb 28 }

  condition:
    any of them
}