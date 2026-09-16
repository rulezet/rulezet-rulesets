rule TTP_XOR_WriteProcessMemory_098e {
  strings:
    $key_098e = { 5e fc [2] 6c de [2] 6a eb [2] 44 eb [2] 7b f7 }

  condition:
    any of them
}