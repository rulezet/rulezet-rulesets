rule TTP_XOR_WriteProcessMemory_15d3 {
  strings:
    $key_15d3 = { 42 a1 [2] 70 83 [2] 76 b6 [2] 58 b6 [2] 67 aa }

  condition:
    any of them
}