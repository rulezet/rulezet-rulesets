rule TTP_XOR_WriteProcessMemory_72f6 {
  strings:
    $key_72f6 = { 25 84 [2] 17 a6 [2] 11 93 [2] 3f 93 [2] 00 8f }

  condition:
    any of them
}