rule TTP_XOR_WriteProcessMemory_30a6 {
  strings:
    $key_30a6 = { 67 d4 [2] 55 f6 [2] 53 c3 [2] 7d c3 [2] 42 df }

  condition:
    any of them
}