rule TTP_XOR_WriteProcessMemory_895f {
  strings:
    $key_895f = { de 2d [2] ec 0f [2] ea 3a [2] c4 3a [2] fb 26 }

  condition:
    any of them
}