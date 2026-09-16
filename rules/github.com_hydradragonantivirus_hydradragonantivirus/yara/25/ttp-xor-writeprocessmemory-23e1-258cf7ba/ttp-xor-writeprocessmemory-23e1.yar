rule TTP_XOR_WriteProcessMemory_23e1 {
  strings:
    $key_23e1 = { 74 93 [2] 46 b1 [2] 40 84 [2] 6e 84 [2] 51 98 }

  condition:
    any of them
}