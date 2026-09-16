rule TTP_XOR_WriteProcessMemory_4d90 {
  strings:
    $key_4d90 = { 1a e2 [2] 28 c0 [2] 2e f5 [2] 00 f5 [2] 3f e9 }

  condition:
    any of them
}