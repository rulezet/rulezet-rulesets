rule TTP_XOR_WriteProcessMemory_2640 {
  strings:
    $key_2640 = { 71 32 [2] 43 10 [2] 45 25 [2] 6b 25 [2] 54 39 }

  condition:
    any of them
}