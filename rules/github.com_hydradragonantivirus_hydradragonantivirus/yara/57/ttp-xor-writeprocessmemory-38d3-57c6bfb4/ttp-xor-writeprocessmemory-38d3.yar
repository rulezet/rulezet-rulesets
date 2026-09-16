rule TTP_XOR_WriteProcessMemory_38d3 {
  strings:
    $key_38d3 = { 6f a1 [2] 5d 83 [2] 5b b6 [2] 75 b6 [2] 4a aa }

  condition:
    any of them
}