rule TTP_XOR_WriteProcessMemory_f6b6 {
  strings:
    $key_f6b6 = { a1 c4 [2] 93 e6 [2] 95 d3 [2] bb d3 [2] 84 cf }

  condition:
    any of them
}