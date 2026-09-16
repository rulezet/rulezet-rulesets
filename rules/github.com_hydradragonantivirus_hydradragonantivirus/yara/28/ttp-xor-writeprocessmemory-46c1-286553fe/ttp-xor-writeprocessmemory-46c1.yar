rule TTP_XOR_WriteProcessMemory_46c1 {
  strings:
    $key_46c1 = { 11 b3 [2] 23 91 [2] 25 a4 [2] 0b a4 [2] 34 b8 }

  condition:
    any of them
}