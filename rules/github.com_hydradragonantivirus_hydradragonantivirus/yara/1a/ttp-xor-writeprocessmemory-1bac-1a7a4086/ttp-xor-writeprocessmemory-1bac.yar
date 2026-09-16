rule TTP_XOR_WriteProcessMemory_1bac {
  strings:
    $key_1bac = { 4c de [2] 7e fc [2] 78 c9 [2] 56 c9 [2] 69 d5 }

  condition:
    any of them
}