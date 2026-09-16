rule TTP_XOR_WriteProcessMemory_896c {
  strings:
    $key_896c = { de 1e [2] ec 3c [2] ea 09 [2] c4 09 [2] fb 15 }

  condition:
    any of them
}