rule TTP_XOR_WriteProcessMemory_8950 {
  strings:
    $key_8950 = { de 22 [2] ec 00 [2] ea 35 [2] c4 35 [2] fb 29 }

  condition:
    any of them
}