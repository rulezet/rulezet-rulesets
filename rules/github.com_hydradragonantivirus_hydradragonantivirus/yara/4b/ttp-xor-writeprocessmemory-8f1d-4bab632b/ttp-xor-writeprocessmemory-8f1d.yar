rule TTP_XOR_WriteProcessMemory_8f1d {
  strings:
    $key_8f1d = { d8 6f [2] ea 4d [2] ec 78 [2] c2 78 [2] fd 64 }

  condition:
    any of them
}