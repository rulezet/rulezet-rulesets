rule TTP_XOR_WriteProcessMemory_07f2 {
  strings:
    $key_07f2 = { 50 80 [2] 62 a2 [2] 64 97 [2] 4a 97 [2] 75 8b }

  condition:
    any of them
}