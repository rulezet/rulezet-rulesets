rule TTP_XOR_WriteProcessMemory_7cac {
  strings:
    $key_7cac = { 2b de [2] 19 fc [2] 1f c9 [2] 31 c9 [2] 0e d5 }

  condition:
    any of them
}