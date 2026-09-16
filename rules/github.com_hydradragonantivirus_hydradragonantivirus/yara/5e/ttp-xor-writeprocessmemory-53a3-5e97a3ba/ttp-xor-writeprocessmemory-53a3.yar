rule TTP_XOR_WriteProcessMemory_53a3 {
  strings:
    $key_53a3 = { 04 d1 [2] 36 f3 [2] 30 c6 [2] 1e c6 [2] 21 da }

  condition:
    any of them
}