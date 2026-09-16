rule TTP_XOR_WriteProcessMemory_9811 {
  strings:
    $key_9811 = { cf 63 [2] fd 41 [2] fb 74 [2] d5 74 [2] ea 68 }

  condition:
    any of them
}