rule TTP_XOR_WriteProcessMemory_46d3 {
  strings:
    $key_46d3 = { 11 a1 [2] 23 83 [2] 25 b6 [2] 0b b6 [2] 34 aa }

  condition:
    any of them
}