rule TTP_XOR_WriteProcessMemory_e98e {
  strings:
    $key_e98e = { be fc [2] 8c de [2] 8a eb [2] a4 eb [2] 9b f7 }

  condition:
    any of them
}