rule TTP_XOR_WriteProcessMemory_74c1 {
  strings:
    $key_74c1 = { 23 b3 [2] 11 91 [2] 17 a4 [2] 39 a4 [2] 06 b8 }

  condition:
    any of them
}