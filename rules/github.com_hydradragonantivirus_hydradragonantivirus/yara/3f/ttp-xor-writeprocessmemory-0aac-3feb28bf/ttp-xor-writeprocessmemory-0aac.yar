rule TTP_XOR_WriteProcessMemory_0aac {
  strings:
    $key_0aac = { 5d de [2] 6f fc [2] 69 c9 [2] 47 c9 [2] 78 d5 }

  condition:
    any of them
}