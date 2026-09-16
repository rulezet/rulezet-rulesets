rule TTP_XOR_WriteProcessMemory_07bb {
  strings:
    $key_07bb = { 50 c9 [2] 62 eb [2] 64 de [2] 4a de [2] 75 c2 }

  condition:
    any of them
}