rule TTP_XOR_WriteProcessMemory_98d1 {
  strings:
    $key_98d1 = { cf a3 [2] fd 81 [2] fb b4 [2] d5 b4 [2] ea a8 }

  condition:
    any of them
}