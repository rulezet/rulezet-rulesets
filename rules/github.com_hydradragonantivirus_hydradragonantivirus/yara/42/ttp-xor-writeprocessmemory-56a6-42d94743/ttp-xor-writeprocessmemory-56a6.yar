rule TTP_XOR_WriteProcessMemory_56a6 {
  strings:
    $key_56a6 = { 01 d4 [2] 33 f6 [2] 35 c3 [2] 1b c3 [2] 24 df }

  condition:
    any of them
}