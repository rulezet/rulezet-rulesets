rule TTP_XOR_WriteProcessMemory_16a6 {
  strings:
    $key_16a6 = { 41 d4 [2] 73 f6 [2] 75 c3 [2] 5b c3 [2] 64 df }

  condition:
    any of them
}