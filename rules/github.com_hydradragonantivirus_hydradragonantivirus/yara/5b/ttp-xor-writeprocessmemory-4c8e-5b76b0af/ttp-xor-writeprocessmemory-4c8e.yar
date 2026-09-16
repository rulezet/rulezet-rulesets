rule TTP_XOR_WriteProcessMemory_4c8e {
  strings:
    $key_4c8e = { 1b fc [2] 29 de [2] 2f eb [2] 01 eb [2] 3e f7 }

  condition:
    any of them
}