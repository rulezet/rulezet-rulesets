rule TTP_XOR_WriteProcessMemory_98e6 {
  strings:
    $key_98e6 = { cf 94 [2] fd b6 [2] fb 83 [2] d5 83 [2] ea 9f }

  condition:
    any of them
}