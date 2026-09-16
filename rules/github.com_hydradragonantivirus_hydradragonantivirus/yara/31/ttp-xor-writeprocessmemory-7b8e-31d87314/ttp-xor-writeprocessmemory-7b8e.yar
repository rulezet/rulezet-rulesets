rule TTP_XOR_WriteProcessMemory_7b8e {
  strings:
    $key_7b8e = { 2c fc [2] 1e de [2] 18 eb [2] 36 eb [2] 09 f7 }

  condition:
    any of them
}