rule TTP_XOR_WriteProcessMemory_77f8 {
  strings:
    $key_77f8 = { 20 8a [2] 12 a8 [2] 14 9d [2] 3a 9d [2] 05 81 }

  condition:
    any of them
}