rule TTP_XOR_WriteProcessMemory_9848 {
  strings:
    $key_9848 = { cf 3a [2] fd 18 [2] fb 2d [2] d5 2d [2] ea 31 }

  condition:
    any of them
}