rule TTP_XOR_WriteProcessMemory_98f2 {
  strings:
    $key_98f2 = { cf 80 [2] fd a2 [2] fb 97 [2] d5 97 [2] ea 8b }

  condition:
    any of them
}