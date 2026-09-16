rule TTP_XOR_WriteProcessMemory_9879 {
  strings:
    $key_9879 = { cf 0b [2] fd 29 [2] fb 1c [2] d5 1c [2] ea 00 }

  condition:
    any of them
}