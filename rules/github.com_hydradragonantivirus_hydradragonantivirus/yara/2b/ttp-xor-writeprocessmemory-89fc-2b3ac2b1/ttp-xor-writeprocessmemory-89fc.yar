rule TTP_XOR_WriteProcessMemory_89fc {
  strings:
    $key_89fc = { de 8e [2] ec ac [2] ea 99 [2] c4 99 [2] fb 85 }

  condition:
    any of them
}