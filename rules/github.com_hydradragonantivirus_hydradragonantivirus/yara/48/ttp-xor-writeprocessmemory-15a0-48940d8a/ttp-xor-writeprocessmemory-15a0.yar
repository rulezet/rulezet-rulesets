rule TTP_XOR_WriteProcessMemory_15a0 {
  strings:
    $key_15a0 = { 42 d2 [2] 70 f0 [2] 76 c5 [2] 58 c5 [2] 67 d9 }

  condition:
    any of them
}