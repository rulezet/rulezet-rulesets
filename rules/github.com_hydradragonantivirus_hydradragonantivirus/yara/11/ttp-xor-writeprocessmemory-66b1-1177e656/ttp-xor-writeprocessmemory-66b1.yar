rule TTP_XOR_WriteProcessMemory_66b1 {
  strings:
    $key_66b1 = { 31 c3 [2] 03 e1 [2] 05 d4 [2] 2b d4 [2] 14 c8 }

  condition:
    any of them
}