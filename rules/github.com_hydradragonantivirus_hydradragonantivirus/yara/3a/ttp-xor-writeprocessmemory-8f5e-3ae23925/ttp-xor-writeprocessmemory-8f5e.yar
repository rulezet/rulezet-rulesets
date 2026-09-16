rule TTP_XOR_WriteProcessMemory_8f5e {
  strings:
    $key_8f5e = { d8 2c [2] ea 0e [2] ec 3b [2] c2 3b [2] fd 27 }

  condition:
    any of them
}