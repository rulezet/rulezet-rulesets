rule TTP_XOR_WriteProcessMemory_d88e {
  strings:
    $key_d88e = { 8f fc [2] bd de [2] bb eb [2] 95 eb [2] aa f7 }

  condition:
    any of them
}