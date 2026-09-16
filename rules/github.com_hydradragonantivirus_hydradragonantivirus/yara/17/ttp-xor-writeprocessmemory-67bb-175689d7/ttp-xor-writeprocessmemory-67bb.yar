rule TTP_XOR_WriteProcessMemory_67bb {
  strings:
    $key_67bb = { 30 c9 [2] 02 eb [2] 04 de [2] 2a de [2] 15 c2 }

  condition:
    any of them
}