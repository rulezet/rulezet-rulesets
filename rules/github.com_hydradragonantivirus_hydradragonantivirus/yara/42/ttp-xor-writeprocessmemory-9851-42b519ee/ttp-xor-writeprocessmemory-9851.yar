rule TTP_XOR_WriteProcessMemory_9851 {
  strings:
    $key_9851 = { cf 23 [2] fd 01 [2] fb 34 [2] d5 34 [2] ea 28 }

  condition:
    any of them
}