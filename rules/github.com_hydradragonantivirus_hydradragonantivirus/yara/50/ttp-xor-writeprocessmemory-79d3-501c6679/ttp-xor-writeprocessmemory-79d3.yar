rule TTP_XOR_WriteProcessMemory_79d3 {
  strings:
    $key_79d3 = { 2e a1 [2] 1c 83 [2] 1a b6 [2] 34 b6 [2] 0b aa }

  condition:
    any of them
}