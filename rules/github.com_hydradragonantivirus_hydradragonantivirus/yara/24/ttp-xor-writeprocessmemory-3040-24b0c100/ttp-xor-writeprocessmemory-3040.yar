rule TTP_XOR_WriteProcessMemory_3040 {
  strings:
    $key_3040 = { 67 32 [2] 55 10 [2] 53 25 [2] 7d 25 [2] 42 39 }

  condition:
    any of them
}