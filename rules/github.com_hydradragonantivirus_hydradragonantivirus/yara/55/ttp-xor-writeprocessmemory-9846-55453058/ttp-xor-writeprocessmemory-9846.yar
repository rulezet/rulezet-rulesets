rule TTP_XOR_WriteProcessMemory_9846 {
  strings:
    $key_9846 = { cf 34 [2] fd 16 [2] fb 23 [2] d5 23 [2] ea 3f }

  condition:
    any of them
}