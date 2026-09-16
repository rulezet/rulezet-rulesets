rule TTP_XOR_WriteProcessMemory_e5c2 {
  strings:
    $key_e5c2 = { b2 b0 [2] 80 92 [2] 86 a7 [2] a8 a7 [2] 97 bb }

  condition:
    any of them
}