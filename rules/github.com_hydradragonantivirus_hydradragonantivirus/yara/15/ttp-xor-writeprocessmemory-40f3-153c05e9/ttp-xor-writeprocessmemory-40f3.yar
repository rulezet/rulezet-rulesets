rule TTP_XOR_WriteProcessMemory_40f3 {
  strings:
    $key_40f3 = { 17 81 [2] 25 a3 [2] 23 96 [2] 0d 96 [2] 32 8a }

  condition:
    any of them
}