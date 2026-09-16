rule TTP_XOR_WriteProcessMemory_c1ac {
  strings:
    $key_c1ac = { 96 de [2] a4 fc [2] a2 c9 [2] 8c c9 [2] b3 d5 }

  condition:
    any of them
}