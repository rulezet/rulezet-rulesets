rule TTP_XOR_WriteProcessMemory_99ac {
  strings:
    $key_99ac = { ce de [2] fc fc [2] fa c9 [2] d4 c9 [2] eb d5 }

  condition:
    any of them
}