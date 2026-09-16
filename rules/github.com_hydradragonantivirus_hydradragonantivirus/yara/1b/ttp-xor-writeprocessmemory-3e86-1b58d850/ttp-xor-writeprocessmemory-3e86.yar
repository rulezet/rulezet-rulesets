rule TTP_XOR_WriteProcessMemory_3e86 {
  strings:
    $key_3e86 = { 69 f4 [2] 5b d6 [2] 5d e3 [2] 73 e3 [2] 4c ff }

  condition:
    any of them
}