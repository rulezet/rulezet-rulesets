rule TTP_XOR_WriteProcessMemory_0ed1 {
  strings:
    $key_0ed1 = { 59 a3 [2] 6b 81 [2] 6d b4 [2] 43 b4 [2] 7c a8 }

  condition:
    any of them
}