rule TTP_XOR_WriteProcessMemory_9869 {
  strings:
    $key_9869 = { cf 1b [2] fd 39 [2] fb 0c [2] d5 0c [2] ea 10 }

  condition:
    any of them
}