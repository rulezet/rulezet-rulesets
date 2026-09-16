rule TTP_XOR_WriteProcessMemory_16ac {
  strings:
    $key_16ac = { 41 de [2] 73 fc [2] 75 c9 [2] 5b c9 [2] 64 d5 }

  condition:
    any of them
}