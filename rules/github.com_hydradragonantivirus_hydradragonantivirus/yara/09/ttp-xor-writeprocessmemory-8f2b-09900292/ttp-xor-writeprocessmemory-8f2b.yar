rule TTP_XOR_WriteProcessMemory_8f2b {
  strings:
    $key_8f2b = { d8 59 [2] ea 7b [2] ec 4e [2] c2 4e [2] fd 52 }

  condition:
    any of them
}