rule TTP_XOR_WriteProcessMemory_13a3 {
  strings:
    $key_13a3 = { 44 d1 [2] 76 f3 [2] 70 c6 [2] 5e c6 [2] 61 da }

  condition:
    any of them
}