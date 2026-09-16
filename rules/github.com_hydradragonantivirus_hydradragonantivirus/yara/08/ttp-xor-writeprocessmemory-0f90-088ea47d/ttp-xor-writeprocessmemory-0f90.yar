rule TTP_XOR_WriteProcessMemory_0f90 {
  strings:
    $key_0f90 = { 58 e2 [2] 6a c0 [2] 6c f5 [2] 42 f5 [2] 7d e9 }

  condition:
    any of them
}