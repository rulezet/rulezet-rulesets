rule TTP_XOR_WriteProcessMemory_72f3 {
  strings:
    $key_72f3 = { 25 81 [2] 17 a3 [2] 11 96 [2] 3f 96 [2] 00 8a }

  condition:
    any of them
}