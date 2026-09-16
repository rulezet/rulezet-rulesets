rule TTP_XOR_WriteProcessMemory_985e {
  strings:
    $key_985e = { cf 2c [2] fd 0e [2] fb 3b [2] d5 3b [2] ea 27 }

  condition:
    any of them
}