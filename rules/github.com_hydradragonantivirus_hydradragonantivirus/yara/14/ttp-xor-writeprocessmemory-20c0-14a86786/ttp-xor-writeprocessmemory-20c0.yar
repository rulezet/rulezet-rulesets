rule TTP_XOR_WriteProcessMemory_20c0 {
  strings:
    $key_20c0 = { 77 b2 [2] 45 90 [2] 43 a5 [2] 6d a5 [2] 52 b9 }

  condition:
    any of them
}