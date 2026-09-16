rule TTP_XOR_WriteProcessMemory_5782 {
  strings:
    $key_5782 = { 00 f0 [2] 32 d2 [2] 34 e7 [2] 1a e7 [2] 25 fb }

  condition:
    any of them
}