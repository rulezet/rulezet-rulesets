rule TTP_XOR_WriteProcessMemory_0abb {
  strings:
    $key_0abb = { 5d c9 [2] 6f eb [2] 69 de [2] 47 de [2] 78 c2 }

  condition:
    any of them
}