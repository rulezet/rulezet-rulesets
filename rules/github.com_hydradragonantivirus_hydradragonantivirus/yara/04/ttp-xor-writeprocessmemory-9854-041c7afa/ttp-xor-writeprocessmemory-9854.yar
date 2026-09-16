rule TTP_XOR_WriteProcessMemory_9854 {
  strings:
    $key_9854 = { cf 26 [2] fd 04 [2] fb 31 [2] d5 31 [2] ea 2d }

  condition:
    any of them
}