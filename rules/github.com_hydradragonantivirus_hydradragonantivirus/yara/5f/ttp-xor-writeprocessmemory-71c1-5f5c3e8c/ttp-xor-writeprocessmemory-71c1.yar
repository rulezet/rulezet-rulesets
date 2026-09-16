rule TTP_XOR_WriteProcessMemory_71c1 {
  strings:
    $key_71c1 = { 26 b3 [2] 14 91 [2] 12 a4 [2] 3c a4 [2] 03 b8 }

  condition:
    any of them
}