rule TTP_XOR_WriteProcessMemory_30c0 {
  strings:
    $key_30c0 = { 67 b2 [2] 55 90 [2] 53 a5 [2] 7d a5 [2] 42 b9 }

  condition:
    any of them
}