rule TTP_XOR_WriteProcessMemory_adac {
  strings:
    $key_adac = { fa de [2] c8 fc [2] ce c9 [2] e0 c9 [2] df d5 }

  condition:
    any of them
}