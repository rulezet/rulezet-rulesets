rule TTP_XOR_WriteProcessMemory_d3b5 {
  strings:
    $key_d3b5 = { 84 c7 [2] b6 e5 [2] b0 d0 [2] 9e d0 [2] a1 cc }

  condition:
    any of them
}