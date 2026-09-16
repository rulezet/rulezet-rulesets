rule TTP_XOR_WriteProcessMemory_20a3 {
  strings:
    $key_20a3 = { 77 d1 [2] 45 f3 [2] 43 c6 [2] 6d c6 [2] 52 da }

  condition:
    any of them
}