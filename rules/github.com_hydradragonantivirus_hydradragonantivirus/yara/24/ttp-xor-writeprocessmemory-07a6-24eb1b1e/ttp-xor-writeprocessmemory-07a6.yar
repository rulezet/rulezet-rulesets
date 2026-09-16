rule TTP_XOR_WriteProcessMemory_07a6 {
  strings:
    $key_07a6 = { 50 d4 [2] 62 f6 [2] 64 c3 [2] 4a c3 [2] 75 df }

  condition:
    any of them
}