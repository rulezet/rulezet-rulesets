rule TTP_XOR_WriteProcessMemory_e0a3 {
  strings:
    $key_e0a3 = { b7 d1 [2] 85 f3 [2] 83 c6 [2] ad c6 [2] 92 da }

  condition:
    any of them
}