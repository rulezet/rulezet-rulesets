rule TTP_XOR_WriteProcessMemory_d7d3 {
  strings:
    $key_d7d3 = { 80 a1 [2] b2 83 [2] b4 b6 [2] 9a b6 [2] a5 aa }

  condition:
    any of them
}