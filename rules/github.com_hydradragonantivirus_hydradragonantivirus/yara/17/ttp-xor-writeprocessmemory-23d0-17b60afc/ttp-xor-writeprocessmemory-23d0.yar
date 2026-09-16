rule TTP_XOR_WriteProcessMemory_23d0 {
  strings:
    $key_23d0 = { 74 a2 [2] 46 80 [2] 40 b5 [2] 6e b5 [2] 51 a9 }

  condition:
    any of them
}