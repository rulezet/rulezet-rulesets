rule TTP_XOR_WriteProcessMemory_9840 {
  strings:
    $key_9840 = { cf 32 [2] fd 10 [2] fb 25 [2] d5 25 [2] ea 39 }

  condition:
    any of them
}