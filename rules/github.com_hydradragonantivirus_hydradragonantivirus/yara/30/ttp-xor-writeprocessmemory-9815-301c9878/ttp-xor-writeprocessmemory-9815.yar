rule TTP_XOR_WriteProcessMemory_9815 {
  strings:
    $key_9815 = { cf 67 [2] fd 45 [2] fb 70 [2] d5 70 [2] ea 6c }

  condition:
    any of them
}