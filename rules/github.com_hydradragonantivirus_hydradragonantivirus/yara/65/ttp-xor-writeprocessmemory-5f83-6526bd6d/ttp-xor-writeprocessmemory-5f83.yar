rule TTP_XOR_WriteProcessMemory_5f83 {
  strings:
    $key_5f83 = { 08 f1 [2] 3a d3 [2] 3c e6 [2] 12 e6 [2] 2d fa }

  condition:
    any of them
}