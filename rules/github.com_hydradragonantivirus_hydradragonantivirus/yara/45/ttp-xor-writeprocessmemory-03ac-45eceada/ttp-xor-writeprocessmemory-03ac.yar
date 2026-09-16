rule TTP_XOR_WriteProcessMemory_03ac {
  strings:
    $key_03ac = { 54 de [2] 66 fc [2] 60 c9 [2] 4e c9 [2] 71 d5 }

  condition:
    any of them
}