rule TTP_XOR_WriteProcessMemory_33a3 {
  strings:
    $key_33a3 = { 64 d1 [2] 56 f3 [2] 50 c6 [2] 7e c6 [2] 41 da }

  condition:
    any of them
}