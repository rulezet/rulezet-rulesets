rule TTP_XOR_WriteProcessMemory_98e7 {
  strings:
    $key_98e7 = { cf 95 [2] fd b7 [2] fb 82 [2] d5 82 [2] ea 9e }

  condition:
    any of them
}