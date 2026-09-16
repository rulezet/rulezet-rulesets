rule TTP_XOR_WriteProcessMemory_13a6 {
  strings:
    $key_13a6 = { 44 d4 [2] 76 f6 [2] 70 c3 [2] 5e c3 [2] 61 df }

  condition:
    any of them
}