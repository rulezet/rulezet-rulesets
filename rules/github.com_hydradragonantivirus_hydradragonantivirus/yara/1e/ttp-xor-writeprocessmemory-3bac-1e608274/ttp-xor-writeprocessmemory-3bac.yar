rule TTP_XOR_WriteProcessMemory_3bac {
  strings:
    $key_3bac = { 6c de [2] 5e fc [2] 58 c9 [2] 76 c9 [2] 49 d5 }

  condition:
    any of them
}