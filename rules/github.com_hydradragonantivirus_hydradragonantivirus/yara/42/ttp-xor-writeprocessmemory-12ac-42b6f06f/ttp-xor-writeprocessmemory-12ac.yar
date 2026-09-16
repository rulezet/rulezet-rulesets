rule TTP_XOR_WriteProcessMemory_12ac {
  strings:
    $key_12ac = { 45 de [2] 77 fc [2] 71 c9 [2] 5f c9 [2] 60 d5 }

  condition:
    any of them
}