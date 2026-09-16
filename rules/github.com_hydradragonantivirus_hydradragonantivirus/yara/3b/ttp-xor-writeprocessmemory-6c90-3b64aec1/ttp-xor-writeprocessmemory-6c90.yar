rule TTP_XOR_WriteProcessMemory_6c90 {
  strings:
    $key_6c90 = { 3b e2 [2] 09 c0 [2] 0f f5 [2] 21 f5 [2] 1e e9 }

  condition:
    any of them
}