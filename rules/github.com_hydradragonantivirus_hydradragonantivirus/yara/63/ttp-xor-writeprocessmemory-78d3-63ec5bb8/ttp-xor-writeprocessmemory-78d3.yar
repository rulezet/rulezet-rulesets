rule TTP_XOR_WriteProcessMemory_78d3 {
  strings:
    $key_78d3 = { 2f a1 [2] 1d 83 [2] 1b b6 [2] 35 b6 [2] 0a aa }

  condition:
    any of them
}