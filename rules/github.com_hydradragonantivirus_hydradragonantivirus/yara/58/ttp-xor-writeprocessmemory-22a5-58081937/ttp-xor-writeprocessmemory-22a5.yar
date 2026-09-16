rule TTP_XOR_WriteProcessMemory_22a5 {
  strings:
    $key_22a5 = { 75 d7 [2] 47 f5 [2] 41 c0 [2] 6f c0 [2] 50 dc }

  condition:
    any of them
}