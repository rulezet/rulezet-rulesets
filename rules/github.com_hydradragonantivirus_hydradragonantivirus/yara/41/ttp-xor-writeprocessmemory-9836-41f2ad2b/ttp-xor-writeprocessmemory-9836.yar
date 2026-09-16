rule TTP_XOR_WriteProcessMemory_9836 {
  strings:
    $key_9836 = { cf 44 [2] fd 66 [2] fb 53 [2] d5 53 [2] ea 4f }

  condition:
    any of them
}