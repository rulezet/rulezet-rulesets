rule TTP_XOR_WriteProcessMemory_9825 {
  strings:
    $key_9825 = { cf 57 [2] fd 75 [2] fb 40 [2] d5 40 [2] ea 5c }

  condition:
    any of them
}