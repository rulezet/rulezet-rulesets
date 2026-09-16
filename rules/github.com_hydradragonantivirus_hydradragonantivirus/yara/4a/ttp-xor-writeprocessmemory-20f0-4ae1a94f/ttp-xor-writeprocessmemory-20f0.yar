rule TTP_XOR_WriteProcessMemory_20f0 {
  strings:
    $key_20f0 = { 77 82 [2] 45 a0 [2] 43 95 [2] 6d 95 [2] 52 89 }

  condition:
    any of them
}