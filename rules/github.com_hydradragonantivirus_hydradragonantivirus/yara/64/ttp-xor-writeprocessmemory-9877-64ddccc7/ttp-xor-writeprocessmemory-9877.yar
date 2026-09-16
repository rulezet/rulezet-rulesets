rule TTP_XOR_WriteProcessMemory_9877 {
  strings:
    $key_9877 = { cf 05 [2] fd 27 [2] fb 12 [2] d5 12 [2] ea 0e }

  condition:
    any of them
}