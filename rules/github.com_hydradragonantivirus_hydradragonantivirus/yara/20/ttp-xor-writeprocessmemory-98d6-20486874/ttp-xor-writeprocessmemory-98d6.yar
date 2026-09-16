rule TTP_XOR_WriteProcessMemory_98d6 {
  strings:
    $key_98d6 = { cf a4 [2] fd 86 [2] fb b3 [2] d5 b3 [2] ea af }

  condition:
    any of them
}