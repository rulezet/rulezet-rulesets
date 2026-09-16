rule TTP_XOR_WriteProcessMemory_11a3 {
  strings:
    $key_11a3 = { 46 d1 [2] 74 f3 [2] 72 c6 [2] 5c c6 [2] 63 da }

  condition:
    any of them
}