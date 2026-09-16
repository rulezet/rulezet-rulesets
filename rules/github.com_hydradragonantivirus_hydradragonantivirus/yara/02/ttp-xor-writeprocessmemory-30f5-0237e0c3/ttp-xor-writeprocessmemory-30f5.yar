rule TTP_XOR_WriteProcessMemory_30f5 {
  strings:
    $key_30f5 = { 67 87 [2] 55 a5 [2] 53 90 [2] 7d 90 [2] 42 8c }

  condition:
    any of them
}