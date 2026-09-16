rule TTP_XOR_WriteProcessMemory_0ba6 {
  strings:
    $key_0ba6 = { 5c d4 [2] 6e f6 [2] 68 c3 [2] 46 c3 [2] 79 df }

  condition:
    any of them
}