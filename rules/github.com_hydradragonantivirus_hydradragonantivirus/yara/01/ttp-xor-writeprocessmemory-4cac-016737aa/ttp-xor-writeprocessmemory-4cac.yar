rule TTP_XOR_WriteProcessMemory_4cac {
  strings:
    $key_4cac = { 1b de [2] 29 fc [2] 2f c9 [2] 01 c9 [2] 3e d5 }

  condition:
    any of them
}