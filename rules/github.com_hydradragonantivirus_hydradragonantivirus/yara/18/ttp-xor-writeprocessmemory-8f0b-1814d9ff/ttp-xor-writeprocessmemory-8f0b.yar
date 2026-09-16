rule TTP_XOR_WriteProcessMemory_8f0b {
  strings:
    $key_8f0b = { d8 79 [2] ea 5b [2] ec 6e [2] c2 6e [2] fd 72 }

  condition:
    any of them
}