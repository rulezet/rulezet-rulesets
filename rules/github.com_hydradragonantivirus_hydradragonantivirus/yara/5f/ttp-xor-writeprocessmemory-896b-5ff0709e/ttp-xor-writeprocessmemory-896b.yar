rule TTP_XOR_WriteProcessMemory_896b {
  strings:
    $key_896b = { de 19 [2] ec 3b [2] ea 0e [2] c4 0e [2] fb 12 }

  condition:
    any of them
}