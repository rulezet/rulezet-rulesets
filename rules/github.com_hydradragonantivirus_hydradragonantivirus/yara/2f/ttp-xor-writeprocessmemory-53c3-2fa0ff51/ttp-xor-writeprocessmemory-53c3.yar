rule TTP_XOR_WriteProcessMemory_53c3 {
  strings:
    $key_53c3 = { 04 b1 [2] 36 93 [2] 30 a6 [2] 1e a6 [2] 21 ba }

  condition:
    any of them
}