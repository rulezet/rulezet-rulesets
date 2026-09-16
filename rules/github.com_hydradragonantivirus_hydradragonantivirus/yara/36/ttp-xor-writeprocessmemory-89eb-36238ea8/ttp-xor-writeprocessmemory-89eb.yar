rule TTP_XOR_WriteProcessMemory_89eb {
  strings:
    $key_89eb = { de 99 [2] ec bb [2] ea 8e [2] c4 8e [2] fb 92 }

  condition:
    any of them
}