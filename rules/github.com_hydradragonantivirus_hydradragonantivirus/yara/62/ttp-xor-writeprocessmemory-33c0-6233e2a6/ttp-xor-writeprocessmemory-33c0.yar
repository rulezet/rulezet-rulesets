rule TTP_XOR_WriteProcessMemory_33c0 {
  strings:
    $key_33c0 = { 64 b2 [2] 56 90 [2] 50 a5 [2] 7e a5 [2] 41 b9 }

  condition:
    any of them
}