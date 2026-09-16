rule TTP_XOR_WriteProcessMemory_2e8e {
  strings:
    $key_2e8e = { 79 fc [2] 4b de [2] 4d eb [2] 63 eb [2] 5c f7 }

  condition:
    any of them
}