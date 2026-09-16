rule TTP_XOR_WriteProcessMemory_895a {
  strings:
    $key_895a = { de 28 [2] ec 0a [2] ea 3f [2] c4 3f [2] fb 23 }

  condition:
    any of them
}