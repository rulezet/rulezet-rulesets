rule TTP_XOR_WriteProcessMemory_6abb {
  strings:
    $key_6abb = { 3d c9 [2] 0f eb [2] 09 de [2] 27 de [2] 18 c2 }

  condition:
    any of them
}