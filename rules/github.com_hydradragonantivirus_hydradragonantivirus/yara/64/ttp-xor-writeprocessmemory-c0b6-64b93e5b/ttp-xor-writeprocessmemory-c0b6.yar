rule TTP_XOR_WriteProcessMemory_c0b6 {
  strings:
    $key_c0b6 = { 97 c4 [2] a5 e6 [2] a3 d3 [2] 8d d3 [2] b2 cf }

  condition:
    any of them
}