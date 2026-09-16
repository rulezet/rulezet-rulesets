rule TTP_XOR_WriteProcessMemory_14a6 {
  strings:
    $key_14a6 = { 43 d4 [2] 71 f6 [2] 77 c3 [2] 59 c3 [2] 66 df }

  condition:
    any of them
}