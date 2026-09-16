rule TTP_XOR_WriteProcessMemory_30ac {
  strings:
    $key_30ac = { 67 de [2] 55 fc [2] 53 c9 [2] 7d c9 [2] 42 d5 }

  condition:
    any of them
}