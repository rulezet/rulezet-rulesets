rule TTP_XOR_WriteProcessMemory_891c {
  strings:
    $key_891c = { de 6e [2] ec 4c [2] ea 79 [2] c4 79 [2] fb 65 }

  condition:
    any of them
}