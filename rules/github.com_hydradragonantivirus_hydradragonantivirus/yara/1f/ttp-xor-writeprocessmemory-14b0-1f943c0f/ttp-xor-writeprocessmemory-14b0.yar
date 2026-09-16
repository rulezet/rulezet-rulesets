rule TTP_XOR_WriteProcessMemory_14b0 {
  strings:
    $key_14b0 = { 43 c2 [2] 71 e0 [2] 77 d5 [2] 59 d5 [2] 66 c9 }

  condition:
    any of them
}