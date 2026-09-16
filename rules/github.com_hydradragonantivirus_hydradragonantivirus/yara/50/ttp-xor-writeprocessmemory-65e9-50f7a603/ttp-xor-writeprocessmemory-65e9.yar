rule TTP_XOR_WriteProcessMemory_65e9 {
  strings:
    $key_65e9 = { 32 9b [2] 00 b9 [2] 06 8c [2] 28 8c [2] 17 90 }

  condition:
    any of them
}