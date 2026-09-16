rule TTP_XOR_WriteProcessMemory_30a3 {
  strings:
    $key_30a3 = { 67 d1 [2] 55 f3 [2] 53 c6 [2] 7d c6 [2] 42 da }

  condition:
    any of them
}