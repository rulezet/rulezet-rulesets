rule TTP_XOR_WriteProcessMemory_5592 {
  strings:
    $key_5592 = { 02 e0 [2] 30 c2 [2] 36 f7 [2] 18 f7 [2] 27 eb }

  condition:
    any of them
}