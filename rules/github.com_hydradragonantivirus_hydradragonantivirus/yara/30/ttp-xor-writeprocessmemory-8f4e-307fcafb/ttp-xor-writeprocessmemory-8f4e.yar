rule TTP_XOR_WriteProcessMemory_8f4e {
  strings:
    $key_8f4e = { d8 3c [2] ea 1e [2] ec 2b [2] c2 2b [2] fd 37 }

  condition:
    any of them
}