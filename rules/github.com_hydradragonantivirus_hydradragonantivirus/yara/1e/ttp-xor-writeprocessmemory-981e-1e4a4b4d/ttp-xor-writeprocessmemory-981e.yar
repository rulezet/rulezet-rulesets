rule TTP_XOR_WriteProcessMemory_981e {
  strings:
    $key_981e = { cf 6c [2] fd 4e [2] fb 7b [2] d5 7b [2] ea 67 }

  condition:
    any of them
}