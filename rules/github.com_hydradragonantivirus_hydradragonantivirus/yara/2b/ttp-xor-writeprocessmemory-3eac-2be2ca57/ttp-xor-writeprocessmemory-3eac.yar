rule TTP_XOR_WriteProcessMemory_3eac {
  strings:
    $key_3eac = { 69 de [2] 5b fc [2] 5d c9 [2] 73 c9 [2] 4c d5 }

  condition:
    any of them
}