rule TTP_XOR_WriteProcessMemory_45c1 {
  strings:
    $key_45c1 = { 12 b3 [2] 20 91 [2] 26 a4 [2] 08 a4 [2] 37 b8 }

  condition:
    any of them
}