rule TTP_XOR_WriteProcessMemory_6cac {
  strings:
    $key_6cac = { 3b de [2] 09 fc [2] 0f c9 [2] 21 c9 [2] 1e d5 }

  condition:
    any of them
}