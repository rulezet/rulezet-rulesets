rule TTP_XOR_WriteProcessMemory_3561 {
  strings:
    $key_3561 = { 62 13 [2] 50 31 [2] 56 04 [2] 78 04 [2] 47 18 }

  condition:
    any of them
}