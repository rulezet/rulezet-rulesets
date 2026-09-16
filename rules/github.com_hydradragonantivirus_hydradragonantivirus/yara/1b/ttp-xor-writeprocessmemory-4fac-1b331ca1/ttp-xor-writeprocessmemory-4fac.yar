rule TTP_XOR_WriteProcessMemory_4fac {
  strings:
    $key_4fac = { 18 de [2] 2a fc [2] 2c c9 [2] 02 c9 [2] 3d d5 }

  condition:
    any of them
}