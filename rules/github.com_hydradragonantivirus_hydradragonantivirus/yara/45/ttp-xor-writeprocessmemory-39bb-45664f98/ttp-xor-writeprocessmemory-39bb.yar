rule TTP_XOR_WriteProcessMemory_39bb {
  strings:
    $key_39bb = { 6e c9 [2] 5c eb [2] 5a de [2] 74 de [2] 4b c2 }

  condition:
    any of them
}