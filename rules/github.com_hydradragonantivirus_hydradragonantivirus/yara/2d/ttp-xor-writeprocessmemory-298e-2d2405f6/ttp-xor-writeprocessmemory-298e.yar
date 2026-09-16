rule TTP_XOR_WriteProcessMemory_298e {
  strings:
    $key_298e = { 7e fc [2] 4c de [2] 4a eb [2] 64 eb [2] 5b f7 }

  condition:
    any of them
}