rule TTP_XOR_WriteProcessMemory_983b {
  strings:
    $key_983b = { cf 49 [2] fd 6b [2] fb 5e [2] d5 5e [2] ea 42 }

  condition:
    any of them
}