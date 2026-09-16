rule TTP_XOR_WriteProcessMemory_d6ac {
  strings:
    $key_d6ac = { 81 de [2] b3 fc [2] b5 c9 [2] 9b c9 [2] a4 d5 }

  condition:
    any of them
}