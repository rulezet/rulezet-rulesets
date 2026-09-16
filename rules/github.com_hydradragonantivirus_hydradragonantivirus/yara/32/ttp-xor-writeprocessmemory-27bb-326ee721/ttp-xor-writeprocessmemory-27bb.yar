rule TTP_XOR_WriteProcessMemory_27bb {
  strings:
    $key_27bb = { 70 c9 [2] 42 eb [2] 44 de [2] 6a de [2] 55 c2 }

  condition:
    any of them
}