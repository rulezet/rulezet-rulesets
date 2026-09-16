rule TTP_XOR_WriteProcessMemory_53ac {
  strings:
    $key_53ac = { 04 de [2] 36 fc [2] 30 c9 [2] 1e c9 [2] 21 d5 }

  condition:
    any of them
}