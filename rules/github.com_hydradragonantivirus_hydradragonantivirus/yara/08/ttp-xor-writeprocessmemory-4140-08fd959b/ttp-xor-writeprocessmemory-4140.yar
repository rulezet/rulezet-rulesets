rule TTP_XOR_WriteProcessMemory_4140 {
  strings:
    $key_4140 = { 16 32 [2] 24 10 [2] 22 25 [2] 0c 25 [2] 33 39 }

  condition:
    any of them
}