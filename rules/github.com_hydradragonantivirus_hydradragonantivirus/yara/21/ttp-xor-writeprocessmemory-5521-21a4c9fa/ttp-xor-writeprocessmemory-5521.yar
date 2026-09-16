rule TTP_XOR_WriteProcessMemory_5521 {
  strings:
    $key_5521 = { 02 53 [2] 30 71 [2] 36 44 [2] 18 44 [2] 27 58 }

  condition:
    any of them
}