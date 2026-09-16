rule TTP_XOR_WriteProcessMemory_50f2 {
  strings:
    $key_50f2 = { 07 80 [2] 35 a2 [2] 33 97 [2] 1d 97 [2] 22 8b }

  condition:
    any of them
}