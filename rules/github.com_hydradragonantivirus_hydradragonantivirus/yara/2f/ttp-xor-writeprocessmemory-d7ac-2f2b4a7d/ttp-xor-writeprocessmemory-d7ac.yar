rule TTP_XOR_WriteProcessMemory_d7ac {
  strings:
    $key_d7ac = { 80 de [2] b2 fc [2] b4 c9 [2] 9a c9 [2] a5 d5 }

  condition:
    any of them
}