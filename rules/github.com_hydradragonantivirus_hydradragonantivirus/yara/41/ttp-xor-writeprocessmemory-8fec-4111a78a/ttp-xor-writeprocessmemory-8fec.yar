rule TTP_XOR_WriteProcessMemory_8fec {
  strings:
    $key_8fec = { d8 9e [2] ea bc [2] ec 89 [2] c2 89 [2] fd 95 }

  condition:
    any of them
}