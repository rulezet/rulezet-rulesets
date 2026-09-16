rule TTP_XOR_WriteProcessMemory_f5a6 {
  strings:
    $key_f5a6 = { a2 d4 [2] 90 f6 [2] 96 c3 [2] b8 c3 [2] 87 df }

  condition:
    any of them
}