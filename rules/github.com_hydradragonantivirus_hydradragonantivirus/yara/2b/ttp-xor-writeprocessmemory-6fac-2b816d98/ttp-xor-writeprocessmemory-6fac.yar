rule TTP_XOR_WriteProcessMemory_6fac {
  strings:
    $key_6fac = { 38 de [2] 0a fc [2] 0c c9 [2] 22 c9 [2] 1d d5 }

  condition:
    any of them
}