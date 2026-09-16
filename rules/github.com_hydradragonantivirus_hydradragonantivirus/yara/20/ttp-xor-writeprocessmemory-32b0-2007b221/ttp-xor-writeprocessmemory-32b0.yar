rule TTP_XOR_WriteProcessMemory_32b0 {
  strings:
    $key_32b0 = { 65 c2 [2] 57 e0 [2] 51 d5 [2] 7f d5 [2] 40 c9 }

  condition:
    any of them
}