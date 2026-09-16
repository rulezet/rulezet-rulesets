rule TTP_XOR_WriteProcessMemory_05b0 {
  strings:
    $key_05b0 = { 52 c2 [2] 60 e0 [2] 66 d5 [2] 48 d5 [2] 77 c9 }

  condition:
    any of them
}