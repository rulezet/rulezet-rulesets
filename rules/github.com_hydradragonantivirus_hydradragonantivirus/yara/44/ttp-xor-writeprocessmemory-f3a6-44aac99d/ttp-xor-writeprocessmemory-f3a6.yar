rule TTP_XOR_WriteProcessMemory_f3a6 {
  strings:
    $key_f3a6 = { a4 d4 [2] 96 f6 [2] 90 c3 [2] be c3 [2] 81 df }

  condition:
    any of them
}