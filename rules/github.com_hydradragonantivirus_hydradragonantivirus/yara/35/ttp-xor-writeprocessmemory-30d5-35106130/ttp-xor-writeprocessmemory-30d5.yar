rule TTP_XOR_WriteProcessMemory_30d5 {
  strings:
    $key_30d5 = { 67 a7 [2] 55 85 [2] 53 b0 [2] 7d b0 [2] 42 ac }

  condition:
    any of them
}