rule TTP_XOR_WriteProcessMemory_22b1 {
  strings:
    $key_22b1 = { 75 c3 [2] 47 e1 [2] 41 d4 [2] 6f d4 [2] 50 c8 }

  condition:
    any of them
}