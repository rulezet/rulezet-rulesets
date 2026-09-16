rule TTP_XOR_WriteProcessMemory_0bac {
  strings:
    $key_0bac = { 5c de [2] 6e fc [2] 68 c9 [2] 46 c9 [2] 79 d5 }

  condition:
    any of them
}