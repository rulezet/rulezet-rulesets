rule TTP_XOR_WriteProcessMemory_8cac {
  strings:
    $key_8cac = { db de [2] e9 fc [2] ef c9 [2] c1 c9 [2] fe d5 }

  condition:
    any of them
}