rule TTP_XOR_WriteProcessMemory_65f2 {
  strings:
    $key_65f2 = { 32 80 [2] 00 a2 [2] 06 97 [2] 28 97 [2] 17 8b }

  condition:
    any of them
}