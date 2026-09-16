rule TTP_XOR_WriteProcessMemory_5abb {
  strings:
    $key_5abb = { 0d c9 [2] 3f eb [2] 39 de [2] 17 de [2] 28 c2 }

  condition:
    any of them
}