rule TTP_XOR_WriteProcessMemory_e5b6 {
  strings:
    $key_e5b6 = { b2 c4 [2] 80 e6 [2] 86 d3 [2] a8 d3 [2] 97 cf }

  condition:
    any of them
}