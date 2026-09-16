rule TTP_XOR_WriteProcessMemory_5190 {
  strings:
    $key_5190 = { 06 e2 [2] 34 c0 [2] 32 f5 [2] 1c f5 [2] 23 e9 }

  condition:
    any of them
}