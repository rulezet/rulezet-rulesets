rule TTP_XOR_WriteProcessMemory_8f6b {
  strings:
    $key_8f6b = { d8 19 [2] ea 3b [2] ec 0e [2] c2 0e [2] fd 12 }

  condition:
    any of them
}