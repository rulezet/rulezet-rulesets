rule TTP_XOR_WriteProcessMemory_14b1 {
  strings:
    $key_14b1 = { 43 c3 [2] 71 e1 [2] 77 d4 [2] 59 d4 [2] 66 c8 }

  condition:
    any of them
}