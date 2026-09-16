rule TTP_XOR_WriteProcessMemory_2cac {
  strings:
    $key_2cac = { 7b de [2] 49 fc [2] 4f c9 [2] 61 c9 [2] 5e d5 }

  condition:
    any of them
}