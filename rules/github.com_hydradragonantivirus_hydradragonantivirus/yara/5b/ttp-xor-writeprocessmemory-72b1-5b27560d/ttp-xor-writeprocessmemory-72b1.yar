rule TTP_XOR_WriteProcessMemory_72b1 {
  strings:
    $key_72b1 = { 25 c3 [2] 17 e1 [2] 11 d4 [2] 3f d4 [2] 00 c8 }

  condition:
    any of them
}