rule TTP_XOR_WriteProcessMemory_efac {
  strings:
    $key_efac = { b8 de [2] 8a fc [2] 8c c9 [2] a2 c9 [2] 9d d5 }

  condition:
    any of them
}