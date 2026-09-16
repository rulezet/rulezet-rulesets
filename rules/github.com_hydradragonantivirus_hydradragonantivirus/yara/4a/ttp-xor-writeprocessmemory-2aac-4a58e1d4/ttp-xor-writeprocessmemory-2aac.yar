rule TTP_XOR_WriteProcessMemory_2aac {
  strings:
    $key_2aac = { 7d de [2] 4f fc [2] 49 c9 [2] 67 c9 [2] 58 d5 }

  condition:
    any of them
}