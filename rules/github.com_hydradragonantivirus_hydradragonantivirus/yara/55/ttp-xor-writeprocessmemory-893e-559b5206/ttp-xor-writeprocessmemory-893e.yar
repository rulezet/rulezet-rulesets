rule TTP_XOR_WriteProcessMemory_893e {
  strings:
    $key_893e = { de 4c [2] ec 6e [2] ea 5b [2] c4 5b [2] fb 47 }

  condition:
    any of them
}