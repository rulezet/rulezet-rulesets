rule TTP_XOR_WriteProcessMemory_27a6 {
  strings:
    $key_27a6 = { 70 d4 [2] 42 f6 [2] 44 c3 [2] 6a c3 [2] 55 df }

  condition:
    any of them
}