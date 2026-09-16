rule TTP_XOR_WriteProcessMemory_15d0 {
  strings:
    $key_15d0 = { 42 a2 [2] 70 80 [2] 76 b5 [2] 58 b5 [2] 67 a9 }

  condition:
    any of them
}