rule TTP_XOR_WriteProcessMemory_1eac {
  strings:
    $key_1eac = { 49 de [2] 7b fc [2] 7d c9 [2] 53 c9 [2] 6c d5 }

  condition:
    any of them
}