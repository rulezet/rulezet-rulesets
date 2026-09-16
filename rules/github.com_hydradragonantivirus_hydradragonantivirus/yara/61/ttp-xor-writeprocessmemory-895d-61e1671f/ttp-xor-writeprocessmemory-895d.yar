rule TTP_XOR_WriteProcessMemory_895d {
  strings:
    $key_895d = { de 2f [2] ec 0d [2] ea 38 [2] c4 38 [2] fb 24 }

  condition:
    any of them
}