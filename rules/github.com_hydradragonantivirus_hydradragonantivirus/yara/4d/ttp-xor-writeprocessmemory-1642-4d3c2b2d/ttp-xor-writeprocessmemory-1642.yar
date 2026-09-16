rule TTP_XOR_WriteProcessMemory_1642 {
  strings:
    $key_1642 = { 41 30 [2] 73 12 [2] 75 27 [2] 5b 27 [2] 64 3b }

  condition:
    any of them
}