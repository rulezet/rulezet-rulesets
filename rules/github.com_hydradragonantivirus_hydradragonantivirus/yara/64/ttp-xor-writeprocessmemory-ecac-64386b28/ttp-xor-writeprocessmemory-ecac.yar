rule TTP_XOR_WriteProcessMemory_ecac {
  strings:
    $key_ecac = { bb de [2] 89 fc [2] 8f c9 [2] a1 c9 [2] 9e d5 }

  condition:
    any of them
}