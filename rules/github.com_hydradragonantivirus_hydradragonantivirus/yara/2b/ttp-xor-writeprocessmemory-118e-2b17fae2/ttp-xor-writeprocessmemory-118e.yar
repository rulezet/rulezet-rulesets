rule TTP_XOR_WriteProcessMemory_118e {
  strings:
    $key_118e = { 46 fc [2] 74 de [2] 72 eb [2] 5c eb [2] 63 f7 }

  condition:
    any of them
}