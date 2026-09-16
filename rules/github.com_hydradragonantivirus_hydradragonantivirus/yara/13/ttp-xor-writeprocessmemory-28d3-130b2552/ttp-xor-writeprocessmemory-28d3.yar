rule TTP_XOR_WriteProcessMemory_28d3 {
  strings:
    $key_28d3 = { 7f a1 [2] 4d 83 [2] 4b b6 [2] 65 b6 [2] 5a aa }

  condition:
    any of them
}