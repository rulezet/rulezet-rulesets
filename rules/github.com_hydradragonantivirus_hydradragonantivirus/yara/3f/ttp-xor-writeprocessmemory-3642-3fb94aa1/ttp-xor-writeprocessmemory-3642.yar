rule TTP_XOR_WriteProcessMemory_3642 {
  strings:
    $key_3642 = { 61 30 [2] 53 12 [2] 55 27 [2] 7b 27 [2] 44 3b }

  condition:
    any of them
}