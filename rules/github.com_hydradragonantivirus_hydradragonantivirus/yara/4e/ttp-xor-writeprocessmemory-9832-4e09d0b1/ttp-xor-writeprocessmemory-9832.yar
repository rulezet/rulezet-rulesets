rule TTP_XOR_WriteProcessMemory_9832 {
  strings:
    $key_9832 = { cf 40 [2] fd 62 [2] fb 57 [2] d5 57 [2] ea 4b }

  condition:
    any of them
}