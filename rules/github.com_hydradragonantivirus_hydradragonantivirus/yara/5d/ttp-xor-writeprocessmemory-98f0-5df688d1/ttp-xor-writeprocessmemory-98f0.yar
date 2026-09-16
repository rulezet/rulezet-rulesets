rule TTP_XOR_WriteProcessMemory_98f0 {
  strings:
    $key_98f0 = { cf 82 [2] fd a0 [2] fb 95 [2] d5 95 [2] ea 89 }

  condition:
    any of them
}