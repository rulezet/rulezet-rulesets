rule TTP_XOR_WriteProcessMemory_98ec {
  strings:
    $key_98ec = { cf 9e [2] fd bc [2] fb 89 [2] d5 89 [2] ea 95 }

  condition:
    any of them
}