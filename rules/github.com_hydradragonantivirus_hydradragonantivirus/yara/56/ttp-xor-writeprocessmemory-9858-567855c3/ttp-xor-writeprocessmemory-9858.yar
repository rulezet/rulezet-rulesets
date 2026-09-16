rule TTP_XOR_WriteProcessMemory_9858 {
  strings:
    $key_9858 = { cf 2a [2] fd 08 [2] fb 3d [2] d5 3d [2] ea 21 }

  condition:
    any of them
}