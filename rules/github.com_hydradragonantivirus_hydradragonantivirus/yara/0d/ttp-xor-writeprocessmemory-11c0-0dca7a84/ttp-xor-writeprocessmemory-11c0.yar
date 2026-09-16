rule TTP_XOR_WriteProcessMemory_11c0 {
  strings:
    $key_11c0 = { 46 b2 [2] 74 90 [2] 72 a5 [2] 5c a5 [2] 63 b9 }

  condition:
    any of them
}