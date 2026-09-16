rule TTP_XOR_WriteProcessMemory_98e3 {
  strings:
    $key_98e3 = { cf 91 [2] fd b3 [2] fb 86 [2] d5 86 [2] ea 9a }

  condition:
    any of them
}