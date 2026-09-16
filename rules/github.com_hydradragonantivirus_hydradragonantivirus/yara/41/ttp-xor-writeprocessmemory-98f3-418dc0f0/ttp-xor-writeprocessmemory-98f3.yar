rule TTP_XOR_WriteProcessMemory_98f3 {
  strings:
    $key_98f3 = { cf 81 [2] fd a3 [2] fb 96 [2] d5 96 [2] ea 8a }

  condition:
    any of them
}