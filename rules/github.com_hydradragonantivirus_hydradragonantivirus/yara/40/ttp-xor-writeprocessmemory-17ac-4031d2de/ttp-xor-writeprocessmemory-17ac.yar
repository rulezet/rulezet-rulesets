rule TTP_XOR_WriteProcessMemory_17ac {
  strings:
    $key_17ac = { 40 de [2] 72 fc [2] 74 c9 [2] 5a c9 [2] 65 d5 }

  condition:
    any of them
}