rule TTP_XOR_WriteProcessMemory_42a3 {
  strings:
    $key_42a3 = { 15 d1 [2] 27 f3 [2] 21 c6 [2] 0f c6 [2] 30 da }

  condition:
    any of them
}