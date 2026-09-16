rule TTP_XOR_WriteProcessMemory_2240 {
  strings:
    $key_2240 = { 75 32 [2] 47 10 [2] 41 25 [2] 6f 25 [2] 50 39 }

  condition:
    any of them
}