rule TTP_XOR_WriteProcessMemory_23d1 {
  strings:
    $key_23d1 = { 74 a3 [2] 46 81 [2] 40 b4 [2] 6e b4 [2] 51 a8 }

  condition:
    any of them
}