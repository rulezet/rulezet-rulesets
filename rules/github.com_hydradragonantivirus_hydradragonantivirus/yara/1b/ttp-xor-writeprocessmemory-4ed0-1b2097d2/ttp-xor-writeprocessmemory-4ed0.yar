rule TTP_XOR_WriteProcessMemory_4ed0 {
  strings:
    $key_4ed0 = { 19 a2 [2] 2b 80 [2] 2d b5 [2] 03 b5 [2] 3c a9 }

  condition:
    any of them
}