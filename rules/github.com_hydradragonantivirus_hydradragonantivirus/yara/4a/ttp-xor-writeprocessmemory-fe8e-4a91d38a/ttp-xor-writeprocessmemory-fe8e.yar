rule TTP_XOR_WriteProcessMemory_fe8e {
  strings:
    $key_fe8e = { a9 fc [2] 9b de [2] 9d eb [2] b3 eb [2] 8c f7 }

  condition:
    any of them
}