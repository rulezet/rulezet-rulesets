rule TTP_XOR_WriteProcessMemory_8912 {
  strings:
    $key_8912 = { de 60 [2] ec 42 [2] ea 77 [2] c4 77 [2] fb 6b }

  condition:
    any of them
}