rule TTP_XOR_WriteProcessMemory_1e80 {
  strings:
    $key_1e80 = { 49 f2 [2] 7b d0 [2] 7d e5 [2] 53 e5 [2] 6c f9 }

  condition:
    any of them
}