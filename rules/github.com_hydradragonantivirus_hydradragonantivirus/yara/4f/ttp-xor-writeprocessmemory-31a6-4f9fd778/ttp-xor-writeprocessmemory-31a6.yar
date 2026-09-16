rule TTP_XOR_WriteProcessMemory_31a6 {
  strings:
    $key_31a6 = { 66 d4 [2] 54 f6 [2] 52 c3 [2] 7c c3 [2] 43 df }

  condition:
    any of them
}