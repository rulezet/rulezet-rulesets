rule TTP_XOR_WriteProcessMemory_06bb {
  strings:
    $key_06bb = { 51 c9 [2] 63 eb [2] 65 de [2] 4b de [2] 74 c2 }

  condition:
    any of them
}