rule TTP_XOR_WriteProcessMemory_0811 {
  strings:
    $key_0811 = { 5f 63 [2] 6d 41 [2] 6b 74 [2] 45 74 [2] 7a 68 }

  condition:
    any of them
}