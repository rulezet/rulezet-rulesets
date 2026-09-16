rule TTP_XOR_WriteProcessMemory_33ac {
  strings:
    $key_33ac = { 64 de [2] 56 fc [2] 50 c9 [2] 7e c9 [2] 41 d5 }

  condition:
    any of them
}