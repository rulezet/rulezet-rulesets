rule TTP_XOR_WriteProcessMemory_3560 {
  strings:
    $key_3560 = { 62 12 [2] 50 30 [2] 56 05 [2] 78 05 [2] 47 19 }

  condition:
    any of them
}