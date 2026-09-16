rule TTP_XOR_WriteProcessMemory_0fac {
  strings:
    $key_0fac = { 58 de [2] 6a fc [2] 6c c9 [2] 42 c9 [2] 7d d5 }

  condition:
    any of them
}