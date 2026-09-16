rule TTP_XOR_WriteProcessMemory_35d0 {
  strings:
    $key_35d0 = { 62 a2 [2] 50 80 [2] 56 b5 [2] 78 b5 [2] 47 a9 }

  condition:
    any of them
}