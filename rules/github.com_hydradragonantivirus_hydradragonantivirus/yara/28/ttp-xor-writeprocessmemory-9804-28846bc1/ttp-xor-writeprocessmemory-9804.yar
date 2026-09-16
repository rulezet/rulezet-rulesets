rule TTP_XOR_WriteProcessMemory_9804 {
  strings:
    $key_9804 = { cf 76 [2] fd 54 [2] fb 61 [2] d5 61 [2] ea 7d }

  condition:
    any of them
}