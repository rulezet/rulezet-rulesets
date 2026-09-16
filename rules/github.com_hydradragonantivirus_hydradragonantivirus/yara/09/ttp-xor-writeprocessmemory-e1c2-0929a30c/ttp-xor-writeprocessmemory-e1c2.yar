rule TTP_XOR_WriteProcessMemory_e1c2 {
  strings:
    $key_e1c2 = { b6 b0 [2] 84 92 [2] 82 a7 [2] ac a7 [2] 93 bb }

  condition:
    any of them
}