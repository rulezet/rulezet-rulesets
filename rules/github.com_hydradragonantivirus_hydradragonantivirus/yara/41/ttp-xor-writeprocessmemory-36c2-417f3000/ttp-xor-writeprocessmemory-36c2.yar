rule TTP_XOR_WriteProcessMemory_36c2 {
  strings:
    $key_36c2 = { 61 b0 [2] 53 92 [2] 55 a7 [2] 7b a7 [2] 44 bb }

  condition:
    any of them
}