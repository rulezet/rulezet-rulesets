rule TTP_XOR_WriteProcessMemory_34b0 {
  strings:
    $key_34b0 = { 63 c2 [2] 51 e0 [2] 57 d5 [2] 79 d5 [2] 46 c9 }

  condition:
    any of them
}