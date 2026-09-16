rule TTP_XOR_WriteProcessMemory_8f5d {
  strings:
    $key_8f5d = { d8 2f [2] ea 0d [2] ec 38 [2] c2 38 [2] fd 24 }

  condition:
    any of them
}