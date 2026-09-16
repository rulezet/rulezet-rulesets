rule TTP_XOR_WriteProcessMemory_75a6 {
  strings:
    $key_75a6 = { 22 d4 [2] 10 f6 [2] 16 c3 [2] 38 c3 [2] 07 df }

  condition:
    any of them
}