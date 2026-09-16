rule TTP_XOR_WriteProcessMemory_0e86 {
  strings:
    $key_0e86 = { 59 f4 [2] 6b d6 [2] 6d e3 [2] 43 e3 [2] 7c ff }

  condition:
    any of them
}