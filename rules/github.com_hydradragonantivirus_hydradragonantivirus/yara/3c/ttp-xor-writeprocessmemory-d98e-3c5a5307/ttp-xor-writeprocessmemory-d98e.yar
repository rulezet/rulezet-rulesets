rule TTP_XOR_WriteProcessMemory_d98e {
  strings:
    $key_d98e = { 8e fc [2] bc de [2] ba eb [2] 94 eb [2] ab f7 }

  condition:
    any of them
}