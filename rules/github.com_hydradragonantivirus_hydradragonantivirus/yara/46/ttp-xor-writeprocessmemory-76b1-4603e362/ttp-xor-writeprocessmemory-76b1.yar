rule TTP_XOR_WriteProcessMemory_76b1 {
  strings:
    $key_76b1 = { 21 c3 [2] 13 e1 [2] 15 d4 [2] 3b d4 [2] 04 c8 }

  condition:
    any of them
}