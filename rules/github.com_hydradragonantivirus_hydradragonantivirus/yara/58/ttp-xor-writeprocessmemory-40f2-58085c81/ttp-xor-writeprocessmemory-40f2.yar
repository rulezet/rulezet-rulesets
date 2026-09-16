rule TTP_XOR_WriteProcessMemory_40f2 {
  strings:
    $key_40f2 = { 17 80 [2] 25 a2 [2] 23 97 [2] 0d 97 [2] 32 8b }

  condition:
    any of them
}