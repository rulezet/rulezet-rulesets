rule TTP_XOR_WriteProcessMemory_53a6 {
  strings:
    $key_53a6 = { 04 d4 [2] 36 f6 [2] 30 c3 [2] 1e c3 [2] 21 df }

  condition:
    any of them
}