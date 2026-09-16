rule TTP_XOR_WriteProcessMemory_12f2 {
  strings:
    $key_12f2 = { 45 80 [2] 77 a2 [2] 71 97 [2] 5f 97 [2] 60 8b }

  condition:
    any of them
}