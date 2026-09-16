rule TTP_XOR_WriteProcessMemory_9838 {
  strings:
    $key_9838 = { cf 4a [2] fd 68 [2] fb 5d [2] d5 5d [2] ea 41 }

  condition:
    any of them
}