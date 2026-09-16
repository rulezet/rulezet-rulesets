rule TTP_XOR_WriteProcessMemory_894a {
  strings:
    $key_894a = { de 38 [2] ec 1a [2] ea 2f [2] c4 2f [2] fb 33 }

  condition:
    any of them
}