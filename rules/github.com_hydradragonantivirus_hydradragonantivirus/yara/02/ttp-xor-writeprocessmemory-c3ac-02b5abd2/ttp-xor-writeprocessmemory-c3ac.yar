rule TTP_XOR_WriteProcessMemory_c3ac {
  strings:
    $key_c3ac = { 94 de [2] a6 fc [2] a0 c9 [2] 8e c9 [2] b1 d5 }

  condition:
    any of them
}