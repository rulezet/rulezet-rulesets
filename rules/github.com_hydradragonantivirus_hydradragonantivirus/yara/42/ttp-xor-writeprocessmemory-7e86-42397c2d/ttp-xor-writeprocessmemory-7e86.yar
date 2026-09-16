rule TTP_XOR_WriteProcessMemory_7e86 {
  strings:
    $key_7e86 = { 29 f4 [2] 1b d6 [2] 1d e3 [2] 33 e3 [2] 0c ff }

  condition:
    any of them
}