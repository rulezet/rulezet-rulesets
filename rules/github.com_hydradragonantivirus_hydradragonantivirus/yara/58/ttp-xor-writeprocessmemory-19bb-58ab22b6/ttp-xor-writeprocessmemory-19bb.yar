rule TTP_XOR_WriteProcessMemory_19bb {
  strings:
    $key_19bb = { 4e c9 [2] 7c eb [2] 7a de [2] 54 de [2] 6b c2 }

  condition:
    any of them
}