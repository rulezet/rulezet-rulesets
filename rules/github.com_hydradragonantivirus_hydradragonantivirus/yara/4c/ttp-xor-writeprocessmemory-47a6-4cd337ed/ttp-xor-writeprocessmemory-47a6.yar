rule TTP_XOR_WriteProcessMemory_47a6 {
  strings:
    $key_47a6 = { 10 d4 [2] 22 f6 [2] 24 c3 [2] 0a c3 [2] 35 df }

  condition:
    any of them
}