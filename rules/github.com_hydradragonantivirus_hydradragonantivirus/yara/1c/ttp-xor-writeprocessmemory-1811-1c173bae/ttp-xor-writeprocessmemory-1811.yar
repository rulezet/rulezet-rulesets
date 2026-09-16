rule TTP_XOR_WriteProcessMemory_1811 {
  strings:
    $key_1811 = { 4f 63 [2] 7d 41 [2] 7b 74 [2] 55 74 [2] 6a 68 }

  condition:
    any of them
}