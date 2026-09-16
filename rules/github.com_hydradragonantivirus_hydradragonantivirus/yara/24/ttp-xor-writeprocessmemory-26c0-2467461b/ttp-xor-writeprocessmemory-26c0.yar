rule TTP_XOR_WriteProcessMemory_26c0 {
  strings:
    $key_26c0 = { 71 b2 [2] 43 90 [2] 45 a5 [2] 6b a5 [2] 54 b9 }

  condition:
    any of them
}