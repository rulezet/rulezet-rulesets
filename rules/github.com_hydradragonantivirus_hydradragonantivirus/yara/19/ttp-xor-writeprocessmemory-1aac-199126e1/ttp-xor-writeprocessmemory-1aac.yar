rule TTP_XOR_WriteProcessMemory_1aac {
  strings:
    $key_1aac = { 4d de [2] 7f fc [2] 79 c9 [2] 57 c9 [2] 68 d5 }

  condition:
    any of them
}