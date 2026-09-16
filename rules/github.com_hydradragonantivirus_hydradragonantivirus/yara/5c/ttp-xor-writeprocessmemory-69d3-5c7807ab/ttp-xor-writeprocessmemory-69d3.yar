rule TTP_XOR_WriteProcessMemory_69d3 {
  strings:
    $key_69d3 = { 3e a1 [2] 0c 83 [2] 0a b6 [2] 24 b6 [2] 1b aa }

  condition:
    any of them
}