rule TTP_XOR_WriteProcessMemory_39ac {
  strings:
    $key_39ac = { 6e de [2] 5c fc [2] 5a c9 [2] 74 c9 [2] 4b d5 }

  condition:
    any of them
}