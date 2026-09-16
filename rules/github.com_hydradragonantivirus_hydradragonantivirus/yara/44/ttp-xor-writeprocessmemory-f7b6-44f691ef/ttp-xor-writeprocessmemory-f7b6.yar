rule TTP_XOR_WriteProcessMemory_f7b6 {
  strings:
    $key_f7b6 = { a0 c4 [2] 92 e6 [2] 94 d3 [2] ba d3 [2] 85 cf }

  condition:
    any of them
}