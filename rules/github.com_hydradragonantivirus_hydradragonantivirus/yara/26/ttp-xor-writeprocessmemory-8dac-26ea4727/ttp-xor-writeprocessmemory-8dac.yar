rule TTP_XOR_WriteProcessMemory_8dac {
  strings:
    $key_8dac = { da de [2] e8 fc [2] ee c9 [2] c0 c9 [2] ff d5 }

  condition:
    any of them
}