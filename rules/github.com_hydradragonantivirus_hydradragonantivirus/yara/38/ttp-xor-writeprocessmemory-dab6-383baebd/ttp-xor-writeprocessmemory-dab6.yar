rule TTP_XOR_WriteProcessMemory_dab6 {
  strings:
    $key_dab6 = { 8d c4 [2] bf e6 [2] b9 d3 [2] 97 d3 [2] a8 cf }

  condition:
    any of them
}