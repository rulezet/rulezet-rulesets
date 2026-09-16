rule TTP_XOR_WriteProcessMemory_26a6 {
  strings:
    $key_26a6 = { 71 d4 [2] 43 f6 [2] 45 c3 [2] 6b c3 [2] 54 df }

  condition:
    any of them
}