rule TTP_XOR_WriteProcessMemory_e690 {
  strings:
    $key_e690 = { b1 e2 [2] 83 c0 [2] 85 f5 [2] ab f5 [2] 94 e9 }

  condition:
    any of them
}