rule TTP_XOR_WriteProcessMemory_0780 {
  strings:
    $key_0780 = { 50 f2 [2] 62 d0 [2] 64 e5 [2] 4a e5 [2] 75 f9 }

  condition:
    any of them
}