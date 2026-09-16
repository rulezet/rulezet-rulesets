rule TTP_XOR_WriteProcessMemory_0ed0 {
  strings:
    $key_0ed0 = { 59 a2 [2] 6b 80 [2] 6d b5 [2] 43 b5 [2] 7c a9 }

  condition:
    any of them
}