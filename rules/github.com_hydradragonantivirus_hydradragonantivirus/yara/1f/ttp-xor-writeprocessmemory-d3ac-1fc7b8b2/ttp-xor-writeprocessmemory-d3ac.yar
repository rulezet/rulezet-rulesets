rule TTP_XOR_WriteProcessMemory_d3ac {
  strings:
    $key_d3ac = { 84 de [2] b6 fc [2] b0 c9 [2] 9e c9 [2] a1 d5 }

  condition:
    any of them
}