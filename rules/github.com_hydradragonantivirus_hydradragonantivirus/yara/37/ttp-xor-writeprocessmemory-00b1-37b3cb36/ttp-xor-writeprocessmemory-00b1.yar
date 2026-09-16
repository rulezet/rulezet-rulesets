rule TTP_XOR_WriteProcessMemory_00b1 {
  strings:
    $key_00b1 = { 57 c3 [2] 65 e1 [2] 63 d4 [2] 4d d4 [2] 72 c8 }

  condition:
    any of them
}