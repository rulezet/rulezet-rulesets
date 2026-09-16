rule TTP_XOR_WriteProcessMemory_5ba3 {
  strings:
    $key_5ba3 = { 0c d1 [2] 3e f3 [2] 38 c6 [2] 16 c6 [2] 29 da }

  condition:
    any of them
}