rule TTP_XOR_WriteProcessMemory_9806 {
  strings:
    $key_9806 = { cf 74 [2] fd 56 [2] fb 63 [2] d5 63 [2] ea 7f }

  condition:
    any of them
}