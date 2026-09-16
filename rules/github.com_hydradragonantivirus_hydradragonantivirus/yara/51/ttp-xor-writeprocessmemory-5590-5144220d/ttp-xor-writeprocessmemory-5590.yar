rule TTP_XOR_WriteProcessMemory_5590 {
  strings:
    $key_5590 = { 02 e2 [2] 30 c0 [2] 36 f5 [2] 18 f5 [2] 27 e9 }

  condition:
    any of them
}