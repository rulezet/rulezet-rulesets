rule TTP_XOR_WriteProcessMemory_51c0 {
  strings:
    $key_51c0 = { 06 b2 [2] 34 90 [2] 32 a5 [2] 1c a5 [2] 23 b9 }

  condition:
    any of them
}