rule TTP_XOR_WriteProcessMemory_98d4 {
  strings:
    $key_98d4 = { cf a6 [2] fd 84 [2] fb b1 [2] d5 b1 [2] ea ad }

  condition:
    any of them
}