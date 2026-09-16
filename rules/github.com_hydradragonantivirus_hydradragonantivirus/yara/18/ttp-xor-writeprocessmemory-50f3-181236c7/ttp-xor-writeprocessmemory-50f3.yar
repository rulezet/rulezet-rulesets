rule TTP_XOR_WriteProcessMemory_50f3 {
  strings:
    $key_50f3 = { 07 81 [2] 35 a3 [2] 33 96 [2] 1d 96 [2] 22 8a }

  condition:
    any of them
}