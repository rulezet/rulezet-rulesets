rule TTP_XOR_WriteProcessMemory_3480 {
  strings:
    $key_3480 = { 63 f2 [2] 51 d0 [2] 57 e5 [2] 79 e5 [2] 46 f9 }

  condition:
    any of them
}