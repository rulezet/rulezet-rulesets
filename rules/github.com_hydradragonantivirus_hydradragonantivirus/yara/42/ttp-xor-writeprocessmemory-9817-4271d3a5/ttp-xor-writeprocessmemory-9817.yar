rule TTP_XOR_WriteProcessMemory_9817 {
  strings:
    $key_9817 = { cf 65 [2] fd 47 [2] fb 72 [2] d5 72 [2] ea 6e }

  condition:
    any of them
}