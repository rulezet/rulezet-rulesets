rule TTP_XOR_WriteProcessMemory_15e1 {
  strings:
    $key_15e1 = { 42 93 [2] 70 b1 [2] 76 84 [2] 58 84 [2] 67 98 }

  condition:
    any of them
}