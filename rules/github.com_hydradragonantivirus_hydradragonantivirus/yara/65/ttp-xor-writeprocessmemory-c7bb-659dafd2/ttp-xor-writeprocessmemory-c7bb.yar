rule TTP_XOR_WriteProcessMemory_c7bb {
  strings:
    $key_c7bb = { 90 c9 [2] a2 eb [2] a4 de [2] 8a de [2] b5 c2 }

  condition:
    any of them
}