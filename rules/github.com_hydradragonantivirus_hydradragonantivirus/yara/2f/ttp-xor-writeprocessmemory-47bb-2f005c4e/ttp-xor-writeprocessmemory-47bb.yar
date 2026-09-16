rule TTP_XOR_WriteProcessMemory_47bb {
  strings:
    $key_47bb = { 10 c9 [2] 22 eb [2] 24 de [2] 0a de [2] 35 c2 }

  condition:
    any of them
}