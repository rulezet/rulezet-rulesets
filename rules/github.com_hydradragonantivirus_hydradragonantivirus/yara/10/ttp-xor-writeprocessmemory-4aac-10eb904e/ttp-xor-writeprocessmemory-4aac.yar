rule TTP_XOR_WriteProcessMemory_4aac {
  strings:
    $key_4aac = { 1d de [2] 2f fc [2] 29 c9 [2] 07 c9 [2] 38 d5 }

  condition:
    any of them
}