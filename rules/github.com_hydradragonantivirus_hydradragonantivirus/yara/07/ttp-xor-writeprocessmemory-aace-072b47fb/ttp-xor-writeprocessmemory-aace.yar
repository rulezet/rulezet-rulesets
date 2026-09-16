rule TTP_XOR_WriteProcessMemory_aace {
  strings:
    $key_aace = { fd bc [2] cf 9e [2] c9 ab [2] e7 ab [2] d8 b7 }

  condition:
    any of them
}