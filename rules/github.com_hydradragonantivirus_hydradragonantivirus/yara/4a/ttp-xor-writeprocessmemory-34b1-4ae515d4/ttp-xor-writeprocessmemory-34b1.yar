rule TTP_XOR_WriteProcessMemory_34b1 {
  strings:
    $key_34b1 = { 63 c3 [2] 51 e1 [2] 57 d4 [2] 79 d4 [2] 46 c8 }

  condition:
    any of them
}