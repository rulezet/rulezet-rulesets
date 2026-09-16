rule TTP_XOR_WriteProcessMemory_12a3 {
  strings:
    $key_12a3 = { 45 d1 [2] 77 f3 [2] 71 c6 [2] 5f c6 [2] 60 da }

  condition:
    any of them
}