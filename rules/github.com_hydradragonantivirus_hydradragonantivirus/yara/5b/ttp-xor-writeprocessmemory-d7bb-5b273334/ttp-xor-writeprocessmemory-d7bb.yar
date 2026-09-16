rule TTP_XOR_WriteProcessMemory_d7bb {
  strings:
    $key_d7bb = { 80 c9 [2] b2 eb [2] b4 de [2] 9a de [2] a5 c2 }

  condition:
    any of them
}