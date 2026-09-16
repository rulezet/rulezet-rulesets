rule TTP_XOR_WriteProcessMemory_7421 {
  strings:
    $key_7421 = { 23 53 [2] 11 71 [2] 17 44 [2] 39 44 [2] 06 58 }

  condition:
    any of them
}