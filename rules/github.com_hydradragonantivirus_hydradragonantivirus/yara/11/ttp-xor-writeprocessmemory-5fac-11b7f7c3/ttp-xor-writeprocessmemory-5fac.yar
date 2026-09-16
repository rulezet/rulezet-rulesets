rule TTP_XOR_WriteProcessMemory_5fac {
  strings:
    $key_5fac = { 08 de [2] 3a fc [2] 3c c9 [2] 12 c9 [2] 2d d5 }

  condition:
    any of them
}