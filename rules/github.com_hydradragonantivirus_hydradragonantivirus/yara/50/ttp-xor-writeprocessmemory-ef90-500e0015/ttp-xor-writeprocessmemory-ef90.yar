rule TTP_XOR_WriteProcessMemory_ef90 {
  strings:
    $key_ef90 = { b8 e2 [2] 8a c0 [2] 8c f5 [2] a2 f5 [2] 9d e9 }

  condition:
    any of them
}