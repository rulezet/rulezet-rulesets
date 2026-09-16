rule TTP_XOR_WriteProcessMemory_15f9 {
  strings:
    $key_15f9 = { 42 8b [2] 70 a9 [2] 76 9c [2] 58 9c [2] 67 80 }

  condition:
    any of them
}