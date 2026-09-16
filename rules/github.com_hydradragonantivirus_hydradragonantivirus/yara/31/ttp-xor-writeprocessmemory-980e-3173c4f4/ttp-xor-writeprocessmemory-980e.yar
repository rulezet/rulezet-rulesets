rule TTP_XOR_WriteProcessMemory_980e {
  strings:
    $key_980e = { cf 7c [2] fd 5e [2] fb 6b [2] d5 6b [2] ea 77 }

  condition:
    any of them
}