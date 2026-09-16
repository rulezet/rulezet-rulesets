rule TTP_XOR_WriteProcessMemory_d6b6 {
  strings:
    $key_d6b6 = { 81 c4 [2] b3 e6 [2] b5 d3 [2] 9b d3 [2] a4 cf }

  condition:
    any of them
}