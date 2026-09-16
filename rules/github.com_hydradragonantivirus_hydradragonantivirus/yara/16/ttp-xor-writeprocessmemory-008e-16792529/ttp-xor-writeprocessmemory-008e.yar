rule TTP_XOR_WriteProcessMemory_008e {
  strings:
    $key_008e = { 57 fc [2] 65 de [2] 63 eb [2] 4d eb [2] 72 f7 }

  condition:
    any of them
}