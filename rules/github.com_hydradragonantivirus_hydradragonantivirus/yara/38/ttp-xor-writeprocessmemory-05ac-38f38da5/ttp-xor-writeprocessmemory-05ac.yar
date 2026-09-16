rule TTP_XOR_WriteProcessMemory_05ac {
  strings:
    $key_05ac = { 52 de [2] 60 fc [2] 66 c9 [2] 48 c9 [2] 77 d5 }

  condition:
    any of them
}