rule TTP_XOR_WriteProcessMemory_26a5 {
  strings:
    $key_26a5 = { 71 d7 [2] 43 f5 [2] 45 c0 [2] 6b c0 [2] 54 dc }

  condition:
    any of them
}