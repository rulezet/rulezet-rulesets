rule TTP_XOR_WriteProcessMemory_07d3 {
  strings:
    $key_07d3 = { 50 a1 [2] 62 83 [2] 64 b6 [2] 4a b6 [2] 75 aa }

  condition:
    any of them
}