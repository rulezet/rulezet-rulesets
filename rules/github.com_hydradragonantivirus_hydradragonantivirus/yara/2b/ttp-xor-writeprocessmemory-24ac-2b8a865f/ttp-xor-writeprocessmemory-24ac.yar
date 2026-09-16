rule TTP_XOR_WriteProcessMemory_24ac {
  strings:
    $key_24ac = { 73 de [2] 41 fc [2] 47 c9 [2] 69 c9 [2] 56 d5 }

  condition:
    any of them
}