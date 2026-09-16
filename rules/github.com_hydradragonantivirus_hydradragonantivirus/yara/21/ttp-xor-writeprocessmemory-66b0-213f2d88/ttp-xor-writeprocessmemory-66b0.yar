rule TTP_XOR_WriteProcessMemory_66b0 {
  strings:
    $key_66b0 = { 31 c2 [2] 03 e0 [2] 05 d5 [2] 2b d5 [2] 14 c9 }

  condition:
    any of them
}