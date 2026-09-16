rule TTP_XOR_WriteProcessMemory_987c {
  strings:
    $key_987c = { cf 0e [2] fd 2c [2] fb 19 [2] d5 19 [2] ea 05 }

  condition:
    any of them
}