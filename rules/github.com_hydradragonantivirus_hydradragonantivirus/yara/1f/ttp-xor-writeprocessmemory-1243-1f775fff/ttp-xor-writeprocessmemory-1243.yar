rule TTP_XOR_WriteProcessMemory_1243 {
  strings:
    $key_1243 = { 45 31 [2] 77 13 [2] 71 26 [2] 5f 26 [2] 60 3a }

  condition:
    any of them
}