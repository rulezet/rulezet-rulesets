rule TTP_XOR_WriteProcessMemory_74d0 {
  strings:
    $key_74d0 = { 23 a2 [2] 11 80 [2] 17 b5 [2] 39 b5 [2] 06 a9 }

  condition:
    any of them
}