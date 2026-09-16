rule TTP_XOR_WriteProcessMemory_8931 {
  strings:
    $key_8931 = { de 43 [2] ec 61 [2] ea 54 [2] c4 54 [2] fb 48 }

  condition:
    any of them
}