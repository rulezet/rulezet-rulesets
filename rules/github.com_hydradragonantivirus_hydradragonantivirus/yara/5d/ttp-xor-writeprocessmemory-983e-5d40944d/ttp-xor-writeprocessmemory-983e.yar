rule TTP_XOR_WriteProcessMemory_983e {
  strings:
    $key_983e = { cf 4c [2] fd 6e [2] fb 5b [2] d5 5b [2] ea 47 }

  condition:
    any of them
}