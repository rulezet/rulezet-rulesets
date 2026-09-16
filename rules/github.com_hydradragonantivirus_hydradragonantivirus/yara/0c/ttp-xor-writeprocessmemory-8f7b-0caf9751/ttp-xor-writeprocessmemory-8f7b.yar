rule TTP_XOR_WriteProcessMemory_8f7b {
  strings:
    $key_8f7b = { d8 09 [2] ea 2b [2] ec 1e [2] c2 1e [2] fd 02 }

  condition:
    any of them
}