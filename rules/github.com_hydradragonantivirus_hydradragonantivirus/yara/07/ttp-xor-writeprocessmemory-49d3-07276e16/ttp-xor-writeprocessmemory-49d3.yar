rule TTP_XOR_WriteProcessMemory_49d3 {
  strings:
    $key_49d3 = { 1e a1 [2] 2c 83 [2] 2a b6 [2] 04 b6 [2] 3b aa }

  condition:
    any of them
}