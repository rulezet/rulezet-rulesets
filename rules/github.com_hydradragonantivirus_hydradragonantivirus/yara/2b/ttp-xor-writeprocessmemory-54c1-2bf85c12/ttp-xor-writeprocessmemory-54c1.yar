rule TTP_XOR_WriteProcessMemory_54c1 {
  strings:
    $key_54c1 = { 03 b3 [2] 31 91 [2] 37 a4 [2] 19 a4 [2] 26 b8 }

  condition:
    any of them
}