rule TTP_XOR_WriteProcessMemory_8f2d {
  strings:
    $key_8f2d = { d8 5f [2] ea 7d [2] ec 48 [2] c2 48 [2] fd 54 }

  condition:
    any of them
}