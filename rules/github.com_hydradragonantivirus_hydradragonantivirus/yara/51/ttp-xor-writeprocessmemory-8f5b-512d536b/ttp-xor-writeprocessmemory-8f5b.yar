rule TTP_XOR_WriteProcessMemory_8f5b {
  strings:
    $key_8f5b = { d8 29 [2] ea 0b [2] ec 3e [2] c2 3e [2] fd 22 }

  condition:
    any of them
}