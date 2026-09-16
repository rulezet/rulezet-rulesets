rule TTP_XOR_WriteProcessMemory_32b1 {
  strings:
    $key_32b1 = { 65 c3 [2] 57 e1 [2] 51 d4 [2] 7f d4 [2] 40 c8 }

  condition:
    any of them
}