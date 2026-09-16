rule TTP_XOR_WriteProcessMemory_42a5 {
  strings:
    $key_42a5 = { 15 d7 [2] 27 f5 [2] 21 c0 [2] 0f c0 [2] 30 dc }

  condition:
    any of them
}