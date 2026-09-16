rule TTP_XOR_WriteProcessMemory_7c90 {
  strings:
    $key_7c90 = { 2b e2 [2] 19 c0 [2] 1f f5 [2] 31 f5 [2] 0e e9 }

  condition:
    any of them
}