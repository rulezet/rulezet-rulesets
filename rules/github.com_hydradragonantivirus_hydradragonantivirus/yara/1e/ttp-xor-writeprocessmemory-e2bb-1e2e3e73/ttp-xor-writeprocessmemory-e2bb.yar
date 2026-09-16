rule TTP_XOR_WriteProcessMemory_e2bb {
  strings:
    $key_e2bb = { b5 c9 [2] 87 eb [2] 81 de [2] af de [2] 90 c2 }

  condition:
    any of them
}