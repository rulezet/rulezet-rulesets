rule TTP_XOR_WriteProcessMemory_72b0 {
  strings:
    $key_72b0 = { 25 c2 [2] 17 e0 [2] 11 d5 [2] 3f d5 [2] 00 c9 }

  condition:
    any of them
}