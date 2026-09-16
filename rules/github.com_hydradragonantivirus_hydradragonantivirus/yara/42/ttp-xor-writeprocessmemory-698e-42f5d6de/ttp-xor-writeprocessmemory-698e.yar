rule TTP_XOR_WriteProcessMemory_698e {
  strings:
    $key_698e = { 3e fc [2] 0c de [2] 0a eb [2] 24 eb [2] 1b f7 }

  condition:
    any of them
}