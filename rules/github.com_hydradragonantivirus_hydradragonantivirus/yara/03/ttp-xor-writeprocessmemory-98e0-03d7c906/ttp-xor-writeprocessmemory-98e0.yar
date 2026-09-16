rule TTP_XOR_WriteProcessMemory_98e0 {
  strings:
    $key_98e0 = { cf 92 [2] fd b0 [2] fb 85 [2] d5 85 [2] ea 99 }

  condition:
    any of them
}