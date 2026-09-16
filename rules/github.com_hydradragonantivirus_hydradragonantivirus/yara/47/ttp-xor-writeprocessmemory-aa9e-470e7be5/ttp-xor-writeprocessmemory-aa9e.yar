rule TTP_XOR_WriteProcessMemory_aa9e {
  strings:
    $key_aa9e = { fd ec [2] cf ce [2] c9 fb [2] e7 fb [2] d8 e7 }

  condition:
    any of them
}