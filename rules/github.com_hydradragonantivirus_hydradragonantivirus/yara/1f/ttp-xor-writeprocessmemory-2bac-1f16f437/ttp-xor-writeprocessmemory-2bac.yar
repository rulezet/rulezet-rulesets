rule TTP_XOR_WriteProcessMemory_2bac {
  strings:
    $key_2bac = { 7c de [2] 4e fc [2] 48 c9 [2] 66 c9 [2] 59 d5 }

  condition:
    any of them
}