rule TTP_XOR_WriteProcessMemory_35b0 {
  strings:
    $key_35b0 = { 62 c2 [2] 50 e0 [2] 56 d5 [2] 78 d5 [2] 47 c9 }

  condition:
    any of them
}