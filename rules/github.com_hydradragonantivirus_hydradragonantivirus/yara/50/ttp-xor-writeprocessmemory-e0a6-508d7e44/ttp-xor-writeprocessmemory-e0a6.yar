rule TTP_XOR_WriteProcessMemory_e0a6 {
  strings:
    $key_e0a6 = { b7 d4 [2] 85 f6 [2] 83 c3 [2] ad c3 [2] 92 df }

  condition:
    any of them
}