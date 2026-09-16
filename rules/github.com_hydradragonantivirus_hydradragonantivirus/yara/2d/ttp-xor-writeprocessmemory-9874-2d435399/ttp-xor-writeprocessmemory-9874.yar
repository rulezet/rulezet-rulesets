rule TTP_XOR_WriteProcessMemory_9874 {
  strings:
    $key_9874 = { cf 06 [2] fd 24 [2] fb 11 [2] d5 11 [2] ea 0d }

  condition:
    any of them
}