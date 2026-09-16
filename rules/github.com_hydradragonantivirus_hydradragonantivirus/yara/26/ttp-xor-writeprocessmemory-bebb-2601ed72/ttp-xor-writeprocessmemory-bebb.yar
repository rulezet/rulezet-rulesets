rule TTP_XOR_WriteProcessMemory_bebb {
  strings:
    $key_bebb = { e9 c9 [2] db eb [2] dd de [2] f3 de [2] cc c2 }

  condition:
    any of them
}