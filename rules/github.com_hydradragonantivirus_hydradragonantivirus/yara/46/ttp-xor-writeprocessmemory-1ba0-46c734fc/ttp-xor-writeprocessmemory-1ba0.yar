rule TTP_XOR_WriteProcessMemory_1ba0 {
  strings:
    $key_1ba0 = { 4c d2 [2] 7e f0 [2] 78 c5 [2] 56 c5 [2] 69 d9 }

  condition:
    any of them
}