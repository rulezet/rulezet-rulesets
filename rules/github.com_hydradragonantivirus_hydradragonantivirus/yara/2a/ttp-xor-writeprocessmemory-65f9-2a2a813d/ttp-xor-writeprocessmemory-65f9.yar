rule TTP_XOR_WriteProcessMemory_65f9 {
  strings:
    $key_65f9 = { 32 8b [2] 00 a9 [2] 06 9c [2] 28 9c [2] 17 80 }

  condition:
    any of them
}