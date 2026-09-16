rule TTP_XOR_WriteProcessMemory_12a6 {
  strings:
    $key_12a6 = { 45 d4 [2] 77 f6 [2] 71 c3 [2] 5f c3 [2] 60 df }

  condition:
    any of them
}