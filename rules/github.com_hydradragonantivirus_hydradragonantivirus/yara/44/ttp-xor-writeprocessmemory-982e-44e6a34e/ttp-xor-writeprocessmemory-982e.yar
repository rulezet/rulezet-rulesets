rule TTP_XOR_WriteProcessMemory_982e {
  strings:
    $key_982e = { cf 5c [2] fd 7e [2] fb 4b [2] d5 4b [2] ea 57 }

  condition:
    any of them
}