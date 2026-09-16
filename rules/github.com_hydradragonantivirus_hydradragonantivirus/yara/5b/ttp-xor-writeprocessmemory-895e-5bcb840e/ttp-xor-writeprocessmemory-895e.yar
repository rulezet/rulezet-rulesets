rule TTP_XOR_WriteProcessMemory_895e {
  strings:
    $key_895e = { de 2c [2] ec 0e [2] ea 3b [2] c4 3b [2] fb 27 }

  condition:
    any of them
}