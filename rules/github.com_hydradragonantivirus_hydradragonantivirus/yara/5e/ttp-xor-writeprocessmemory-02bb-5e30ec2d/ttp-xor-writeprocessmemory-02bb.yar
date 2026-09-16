rule TTP_XOR_WriteProcessMemory_02bb {
  strings:
    $key_02bb = { 55 c9 [2] 67 eb [2] 61 de [2] 4f de [2] 70 c2 }

  condition:
    any of them
}