rule TTP_XOR_WriteProcessMemory_0b8e {
  strings:
    $key_0b8e = { 5c fc [2] 6e de [2] 68 eb [2] 46 eb [2] 79 f7 }

  condition:
    any of them
}