rule TTP_XOR_WriteProcessMemory_028e {
  strings:
    $key_028e = { 55 fc [2] 67 de [2] 61 eb [2] 4f eb [2] 70 f7 }

  condition:
    any of them
}