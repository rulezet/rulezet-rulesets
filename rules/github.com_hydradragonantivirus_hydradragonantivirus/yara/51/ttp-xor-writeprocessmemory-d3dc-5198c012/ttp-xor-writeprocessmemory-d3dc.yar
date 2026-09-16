rule TTP_XOR_WriteProcessMemory_d3dc {
  strings:
    $key_d3dc = { 84 ae [2] b6 8c [2] b0 b9 [2] 9e b9 [2] a1 a5 }

  condition:
    any of them
}