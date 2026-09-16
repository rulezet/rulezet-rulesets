rule TTP_XOR_WriteProcessMemory_4c90 {
  strings:
    $key_4c90 = { 1b e2 [2] 29 c0 [2] 2f f5 [2] 01 f5 [2] 3e e9 }

  condition:
    any of them
}