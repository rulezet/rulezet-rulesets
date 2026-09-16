rule TTP_XOR_WriteProcessMemory_06e1 {
  strings:
    $key_06e1 = { 51 93 [2] 63 b1 [2] 65 84 [2] 4b 84 [2] 74 98 }

  condition:
    any of them
}