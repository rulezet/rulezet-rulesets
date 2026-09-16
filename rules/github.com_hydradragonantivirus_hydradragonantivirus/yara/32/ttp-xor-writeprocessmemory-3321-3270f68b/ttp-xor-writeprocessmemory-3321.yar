rule TTP_XOR_WriteProcessMemory_3321 {
  strings:
    $key_3321 = { 64 53 [2] 56 71 [2] 50 44 [2] 7e 44 [2] 41 58 }

  condition:
    any of them
}