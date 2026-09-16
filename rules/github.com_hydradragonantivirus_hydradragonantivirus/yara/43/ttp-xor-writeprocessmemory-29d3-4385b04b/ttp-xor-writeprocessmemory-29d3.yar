rule TTP_XOR_WriteProcessMemory_29d3 {
  strings:
    $key_29d3 = { 7e a1 [2] 4c 83 [2] 4a b6 [2] 64 b6 [2] 5b aa }

  condition:
    any of them
}