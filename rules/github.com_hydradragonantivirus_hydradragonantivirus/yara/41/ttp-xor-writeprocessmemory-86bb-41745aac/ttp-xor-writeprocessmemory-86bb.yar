rule TTP_XOR_WriteProcessMemory_86bb {
  strings:
    $key_86bb = { d1 c9 [2] e3 eb [2] e5 de [2] cb de [2] f4 c2 }

  condition:
    any of them
}