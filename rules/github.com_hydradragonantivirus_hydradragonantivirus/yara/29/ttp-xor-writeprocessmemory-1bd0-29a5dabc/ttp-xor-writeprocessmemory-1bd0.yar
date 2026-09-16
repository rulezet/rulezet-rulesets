rule TTP_XOR_WriteProcessMemory_1bd0 {
  strings:
    $key_1bd0 = { 4c a2 [2] 7e 80 [2] 78 b5 [2] 56 b5 [2] 69 a9 }

  condition:
    any of them
}