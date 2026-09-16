rule TTP_XOR_WriteProcessMemory_7f90 {
  strings:
    $key_7f90 = { 28 e2 [2] 1a c0 [2] 1c f5 [2] 32 f5 [2] 0d e9 }

  condition:
    any of them
}