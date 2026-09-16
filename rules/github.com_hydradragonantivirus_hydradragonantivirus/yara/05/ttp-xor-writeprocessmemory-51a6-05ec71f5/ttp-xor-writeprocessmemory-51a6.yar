rule TTP_XOR_WriteProcessMemory_51a6 {
  strings:
    $key_51a6 = { 06 d4 [2] 34 f6 [2] 32 c3 [2] 1c c3 [2] 23 df }

  condition:
    any of them
}