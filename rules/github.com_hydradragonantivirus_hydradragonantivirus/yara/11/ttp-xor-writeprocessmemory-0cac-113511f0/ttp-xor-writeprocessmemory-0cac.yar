rule TTP_XOR_WriteProcessMemory_0cac {
  strings:
    $key_0cac = { 5b de [2] 69 fc [2] 6f c9 [2] 41 c9 [2] 7e d5 }

  condition:
    any of them
}