rule TTP_XOR_WriteProcessMemory_c0ac {
  strings:
    $key_c0ac = { 97 de [2] a5 fc [2] a3 c9 [2] 8d c9 [2] b2 d5 }

  condition:
    any of them
}