rule TTP_XOR_WriteProcessMemory_22f3 {
  strings:
    $key_22f3 = { 75 81 [2] 47 a3 [2] 41 96 [2] 6f 96 [2] 50 8a }

  condition:
    any of them
}