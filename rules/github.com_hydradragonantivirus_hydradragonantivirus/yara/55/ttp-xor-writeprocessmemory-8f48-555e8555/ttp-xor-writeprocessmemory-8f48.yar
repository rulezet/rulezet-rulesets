rule TTP_XOR_WriteProcessMemory_8f48 {
  strings:
    $key_8f48 = { d8 3a [2] ea 18 [2] ec 2d [2] c2 2d [2] fd 31 }

  condition:
    any of them
}