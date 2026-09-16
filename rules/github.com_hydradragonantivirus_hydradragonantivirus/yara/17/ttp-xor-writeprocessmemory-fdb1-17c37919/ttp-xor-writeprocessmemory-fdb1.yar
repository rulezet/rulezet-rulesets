rule TTP_XOR_WriteProcessMemory_fdb1 {
  strings:
    $key_fdb1 = { aa c3 [2] 98 e1 [2] 9e d4 [2] b0 d4 [2] 8f c8 }

  condition:
    any of them
}