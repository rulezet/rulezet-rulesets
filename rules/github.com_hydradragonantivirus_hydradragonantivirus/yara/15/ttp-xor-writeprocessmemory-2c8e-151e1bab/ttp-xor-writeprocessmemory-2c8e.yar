rule TTP_XOR_WriteProcessMemory_2c8e {
  strings:
    $key_2c8e = { 7b fc [2] 49 de [2] 4f eb [2] 61 eb [2] 5e f7 }

  condition:
    any of them
}