rule TTP_XOR_WriteProcessMemory_59d3 {
  strings:
    $key_59d3 = { 0e a1 [2] 3c 83 [2] 3a b6 [2] 14 b6 [2] 2b aa }

  condition:
    any of them
}