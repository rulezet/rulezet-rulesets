rule TTP_XOR_WriteProcessMemory_11a6 {
  strings:
    $key_11a6 = { 46 d4 [2] 74 f6 [2] 72 c3 [2] 5c c3 [2] 63 df }

  condition:
    any of them
}