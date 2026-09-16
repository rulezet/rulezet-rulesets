rule TTP_XOR_WriteProcessMemory_5fa0 {
  strings:
    $key_5fa0 = { 08 d2 [2] 3a f0 [2] 3c c5 [2] 12 c5 [2] 2d d9 }

  condition:
    any of them
}