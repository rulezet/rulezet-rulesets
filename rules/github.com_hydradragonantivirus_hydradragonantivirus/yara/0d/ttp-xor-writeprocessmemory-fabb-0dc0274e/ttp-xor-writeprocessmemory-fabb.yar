rule TTP_XOR_WriteProcessMemory_fabb {
  strings:
    $key_fabb = { ad c9 [2] 9f eb [2] 99 de [2] b7 de [2] 88 c2 }

  condition:
    any of them
}