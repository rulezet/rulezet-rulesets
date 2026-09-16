rule TTP_XOR_WriteProcessMemory_11ac {
  strings:
    $key_11ac = { 46 de [2] 74 fc [2] 72 c9 [2] 5c c9 [2] 63 d5 }

  condition:
    any of them
}