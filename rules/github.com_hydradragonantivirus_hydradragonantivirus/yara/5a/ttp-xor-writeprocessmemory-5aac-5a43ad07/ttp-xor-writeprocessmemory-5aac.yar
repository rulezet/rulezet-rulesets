rule TTP_XOR_WriteProcessMemory_5aac {
  strings:
    $key_5aac = { 0d de [2] 3f fc [2] 39 c9 [2] 17 c9 [2] 28 d5 }

  condition:
    any of them
}