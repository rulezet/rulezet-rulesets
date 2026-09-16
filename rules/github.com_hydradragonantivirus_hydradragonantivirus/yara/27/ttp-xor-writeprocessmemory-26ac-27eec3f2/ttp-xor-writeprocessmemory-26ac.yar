rule TTP_XOR_WriteProcessMemory_26ac {
  strings:
    $key_26ac = { 71 de [2] 43 fc [2] 45 c9 [2] 6b c9 [2] 54 d5 }

  condition:
    any of them
}