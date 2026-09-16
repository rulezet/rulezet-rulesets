rule TTP_XOR_WriteProcessMemory_528e {
  strings:
    $key_528e = { 05 fc [2] 37 de [2] 31 eb [2] 1f eb [2] 20 f7 }

  condition:
    any of them
}