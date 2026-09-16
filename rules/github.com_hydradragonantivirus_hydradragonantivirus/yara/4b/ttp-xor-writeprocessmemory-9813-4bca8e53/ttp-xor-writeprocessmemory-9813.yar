rule TTP_XOR_WriteProcessMemory_9813 {
  strings:
    $key_9813 = { cf 61 [2] fd 43 [2] fb 76 [2] d5 76 [2] ea 6a }

  condition:
    any of them
}