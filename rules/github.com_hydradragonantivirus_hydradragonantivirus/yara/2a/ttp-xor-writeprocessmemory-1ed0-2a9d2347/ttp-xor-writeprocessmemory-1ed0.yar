rule TTP_XOR_WriteProcessMemory_1ed0 {
  strings:
    $key_1ed0 = { 49 a2 [2] 7b 80 [2] 7d b5 [2] 53 b5 [2] 6c a9 }

  condition:
    any of them
}