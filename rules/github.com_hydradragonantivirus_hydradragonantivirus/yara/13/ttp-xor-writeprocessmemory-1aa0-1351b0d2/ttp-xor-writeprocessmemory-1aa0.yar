rule TTP_XOR_WriteProcessMemory_1aa0 {
  strings:
    $key_1aa0 = { 4d d2 [2] 7f f0 [2] 79 c5 [2] 57 c5 [2] 68 d9 }

  condition:
    any of them
}