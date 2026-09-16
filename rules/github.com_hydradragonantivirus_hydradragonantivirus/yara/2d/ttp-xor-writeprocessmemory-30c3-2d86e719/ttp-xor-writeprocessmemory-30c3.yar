rule TTP_XOR_WriteProcessMemory_30c3 {
  strings:
    $key_30c3 = { 67 b1 [2] 55 93 [2] 53 a6 [2] 7d a6 [2] 42 ba }

  condition:
    any of them
}