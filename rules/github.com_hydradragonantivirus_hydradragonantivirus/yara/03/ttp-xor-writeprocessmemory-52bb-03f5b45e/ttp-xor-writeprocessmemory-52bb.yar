rule TTP_XOR_WriteProcessMemory_52bb {
  strings:
    $key_52bb = { 05 c9 [2] 37 eb [2] 31 de [2] 1f de [2] 20 c2 }

  condition:
    any of them
}