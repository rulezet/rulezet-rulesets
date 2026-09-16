rule TTP_XOR_WriteProcessMemory_d0ac {
  strings:
    $key_d0ac = { 87 de [2] b5 fc [2] b3 c9 [2] 9d c9 [2] a2 d5 }

  condition:
    any of them
}