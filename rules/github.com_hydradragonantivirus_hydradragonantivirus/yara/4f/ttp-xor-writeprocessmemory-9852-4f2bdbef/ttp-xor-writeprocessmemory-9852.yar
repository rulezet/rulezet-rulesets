rule TTP_XOR_WriteProcessMemory_9852 {
  strings:
    $key_9852 = { cf 20 [2] fd 02 [2] fb 37 [2] d5 37 [2] ea 2b }

  condition:
    any of them
}