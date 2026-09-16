rule TTP_XOR_WriteProcessMemory_77f9 {
  strings:
    $key_77f9 = { 20 8b [2] 12 a9 [2] 14 9c [2] 3a 9c [2] 05 80 }

  condition:
    any of them
}