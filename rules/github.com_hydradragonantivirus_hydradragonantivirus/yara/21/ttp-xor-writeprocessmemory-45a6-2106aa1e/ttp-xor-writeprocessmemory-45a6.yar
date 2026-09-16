rule TTP_XOR_WriteProcessMemory_45a6 {
  strings:
    $key_45a6 = { 12 d4 [2] 20 f6 [2] 26 c3 [2] 08 c3 [2] 37 df }

  condition:
    any of them
}