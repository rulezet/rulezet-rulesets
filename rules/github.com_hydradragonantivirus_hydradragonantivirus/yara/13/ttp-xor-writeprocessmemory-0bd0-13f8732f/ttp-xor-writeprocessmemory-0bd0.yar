rule TTP_XOR_WriteProcessMemory_0bd0 {
  strings:
    $key_0bd0 = { 5c a2 [2] 6e 80 [2] 68 b5 [2] 46 b5 [2] 79 a9 }

  condition:
    any of them
}