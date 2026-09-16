rule TTP_XOR_WriteProcessMemory_3382 {
  strings:
    $key_3382 = { 64 f0 [2] 56 d2 [2] 50 e7 [2] 7e e7 [2] 41 fb }

  condition:
    any of them
}