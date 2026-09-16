rule TTP_XOR_WriteProcessMemory_26bb {
  strings:
    $key_26bb = { 71 c9 [2] 43 eb [2] 45 de [2] 6b de [2] 54 c2 }

  condition:
    any of them
}