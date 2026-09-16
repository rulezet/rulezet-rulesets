rule TTP_XOR_WriteProcessMemory_9845 {
  strings:
    $key_9845 = { cf 37 [2] fd 15 [2] fb 20 [2] d5 20 [2] ea 3c }

  condition:
    any of them
}