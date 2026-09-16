rule TTP_XOR_WriteProcessMemory_10ac {
  strings:
    $key_10ac = { 47 de [2] 75 fc [2] 73 c9 [2] 5d c9 [2] 62 d5 }

  condition:
    any of them
}