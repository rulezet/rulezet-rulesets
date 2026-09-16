rule TTP_XOR_WriteProcessMemory_3e8e {
  strings:
    $key_3e8e = { 69 fc [2] 5b de [2] 5d eb [2] 73 eb [2] 4c f7 }

  condition:
    any of them
}