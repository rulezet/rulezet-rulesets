rule TTP_XOR_WriteProcessMemory_8f68 {
  strings:
    $key_8f68 = { d8 1a [2] ea 38 [2] ec 0d [2] c2 0d [2] fd 11 }

  condition:
    any of them
}