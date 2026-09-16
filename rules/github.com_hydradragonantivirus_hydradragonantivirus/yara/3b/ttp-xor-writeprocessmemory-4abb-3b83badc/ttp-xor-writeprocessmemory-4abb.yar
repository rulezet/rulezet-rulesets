rule TTP_XOR_WriteProcessMemory_4abb {
  strings:
    $key_4abb = { 1d c9 [2] 2f eb [2] 29 de [2] 07 de [2] 38 c2 }

  condition:
    any of them
}