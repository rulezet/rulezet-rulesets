rule TTP_XOR_WriteProcessMemory_15a5 {
  strings:
    $key_15a5 = { 42 d7 [2] 70 f5 [2] 76 c0 [2] 58 c0 [2] 67 dc }

  condition:
    any of them
}