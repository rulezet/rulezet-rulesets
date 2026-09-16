rule TTP_XOR_WriteProcessMemory_9870 {
  strings:
    $key_9870 = { cf 02 [2] fd 20 [2] fb 15 [2] d5 15 [2] ea 09 }

  condition:
    any of them
}