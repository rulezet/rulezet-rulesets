rule TTP_XOR_WriteProcessMemory_e0d0 {
  strings:
    $key_e0d0 = { b7 a2 [2] 85 80 [2] 83 b5 [2] ad b5 [2] 92 a9 }

  condition:
    any of them
}