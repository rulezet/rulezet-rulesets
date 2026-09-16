rule TTP_XOR_WriteProcessMemory_14a7 {
  strings:
    $key_14a7 = { 43 d5 [2] 71 f7 [2] 77 c2 [2] 59 c2 [2] 66 de }

  condition:
    any of them
}