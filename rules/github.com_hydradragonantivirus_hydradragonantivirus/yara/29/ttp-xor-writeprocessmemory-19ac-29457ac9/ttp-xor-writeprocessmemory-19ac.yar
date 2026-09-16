rule TTP_XOR_WriteProcessMemory_19ac {
  strings:
    $key_19ac = { 4e de [2] 7c fc [2] 7a c9 [2] 54 c9 [2] 6b d5 }

  condition:
    any of them
}