rule TTP_XOR_WriteProcessMemory_98f5 {
  strings:
    $key_98f5 = { cf 87 [2] fd a5 [2] fb 90 [2] d5 90 [2] ea 8c }

  condition:
    any of them
}