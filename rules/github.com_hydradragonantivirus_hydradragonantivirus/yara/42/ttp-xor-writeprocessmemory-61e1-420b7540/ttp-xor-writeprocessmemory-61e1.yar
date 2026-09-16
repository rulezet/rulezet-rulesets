rule TTP_XOR_WriteProcessMemory_61e1 {
  strings:
    $key_61e1 = { 36 93 [2] 04 b1 [2] 02 84 [2] 2c 84 [2] 13 98 }

  condition:
    any of them
}