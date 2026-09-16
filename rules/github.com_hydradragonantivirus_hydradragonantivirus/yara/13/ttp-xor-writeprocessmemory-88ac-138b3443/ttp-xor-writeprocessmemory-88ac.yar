rule TTP_XOR_WriteProcessMemory_88ac {
  strings:
    $key_88ac = { df de [2] ed fc [2] eb c9 [2] c5 c9 [2] fa d5 }

  condition:
    any of them
}