rule TTP_XOR_WriteProcessMemory_30c5 {
  strings:
    $key_30c5 = { 67 b7 [2] 55 95 [2] 53 a0 [2] 7d a0 [2] 42 bc }

  condition:
    any of them
}