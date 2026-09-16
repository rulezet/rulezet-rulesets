rule TTP_XOR_WriteProcessMemory_7abb {
  strings:
    $key_7abb = { 2d c9 [2] 1f eb [2] 19 de [2] 37 de [2] 08 c2 }

  condition:
    any of them
}