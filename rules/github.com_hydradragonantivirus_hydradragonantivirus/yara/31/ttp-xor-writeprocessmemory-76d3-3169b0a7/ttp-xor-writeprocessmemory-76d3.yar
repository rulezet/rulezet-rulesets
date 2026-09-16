rule TTP_XOR_WriteProcessMemory_76d3 {
  strings:
    $key_76d3 = { 21 a1 [2] 13 83 [2] 15 b6 [2] 3b b6 [2] 04 aa }

  condition:
    any of them
}