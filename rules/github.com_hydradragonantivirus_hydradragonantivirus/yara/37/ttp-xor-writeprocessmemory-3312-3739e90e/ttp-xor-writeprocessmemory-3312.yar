rule TTP_XOR_WriteProcessMemory_3312 {
  strings:
    $key_3312 = { 64 60 [2] 56 42 [2] 50 77 [2] 7e 77 [2] 41 6b }

  condition:
    any of them
}