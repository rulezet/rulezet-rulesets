rule TTP_XOR_WriteProcessMemory_3f90 {
  strings:
    $key_3f90 = { 68 e2 [2] 5a c0 [2] 5c f5 [2] 72 f5 [2] 4d e9 }

  condition:
    any of them
}