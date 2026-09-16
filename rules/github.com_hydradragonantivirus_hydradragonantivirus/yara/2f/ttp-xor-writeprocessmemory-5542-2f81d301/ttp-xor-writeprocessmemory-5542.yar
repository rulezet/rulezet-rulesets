rule TTP_XOR_WriteProcessMemory_5542 {
  strings:
    $key_5542 = { 02 30 [2] 30 12 [2] 36 27 [2] 18 27 [2] 27 3b }

  condition:
    any of them
}