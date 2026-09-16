rule TTP_XOR_WriteProcessMemory_5c90 {
  strings:
    $key_5c90 = { 0b e2 [2] 39 c0 [2] 3f f5 [2] 11 f5 [2] 2e e9 }

  condition:
    any of them
}