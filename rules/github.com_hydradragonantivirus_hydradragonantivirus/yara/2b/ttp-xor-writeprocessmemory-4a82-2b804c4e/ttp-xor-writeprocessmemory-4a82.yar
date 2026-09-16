rule TTP_XOR_WriteProcessMemory_4a82 {
  strings:
    $key_4a82 = { 1d f0 [2] 2f d2 [2] 29 e7 [2] 07 e7 [2] 38 fb }

  condition:
    any of them
}