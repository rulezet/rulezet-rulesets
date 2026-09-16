rule TTP_XOR_WriteProcessMemory_67d3 {
  strings:
    $key_67d3 = { 30 a1 [2] 02 83 [2] 04 b6 [2] 2a b6 [2] 15 aa }

  condition:
    any of them
}