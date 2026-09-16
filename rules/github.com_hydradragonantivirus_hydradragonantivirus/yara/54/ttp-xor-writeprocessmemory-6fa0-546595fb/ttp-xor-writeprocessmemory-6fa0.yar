rule TTP_XOR_WriteProcessMemory_6fa0 {
  strings:
    $key_6fa0 = { 38 d2 [2] 0a f0 [2] 0c c5 [2] 22 c5 [2] 1d d9 }

  condition:
    any of them
}