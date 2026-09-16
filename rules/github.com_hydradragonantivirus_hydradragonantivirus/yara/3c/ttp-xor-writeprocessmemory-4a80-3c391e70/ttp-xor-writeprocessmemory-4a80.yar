rule TTP_XOR_WriteProcessMemory_4a80 {
  strings:
    $key_4a80 = { 1d f2 [2] 2f d0 [2] 29 e5 [2] 07 e5 [2] 38 f9 }

  condition:
    any of them
}