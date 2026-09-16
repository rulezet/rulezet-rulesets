rule TTP_XOR_WriteProcessMemory_9818 {
  strings:
    $key_9818 = { cf 6a [2] fd 48 [2] fb 7d [2] d5 7d [2] ea 61 }

  condition:
    any of them
}