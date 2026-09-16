rule TTP_XOR_WriteProcessMemory_c9bb {
  strings:
    $key_c9bb = { 9e c9 [2] ac eb [2] aa de [2] 84 de [2] bb c2 }

  condition:
    any of them
}