rule TTP_XOR_WriteProcessMemory_9849 {
  strings:
    $key_9849 = { cf 3b [2] fd 19 [2] fb 2c [2] d5 2c [2] ea 30 }

  condition:
    any of them
}