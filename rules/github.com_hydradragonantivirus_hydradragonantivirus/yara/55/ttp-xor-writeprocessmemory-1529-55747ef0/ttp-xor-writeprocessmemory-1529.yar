rule TTP_XOR_WriteProcessMemory_1529 {
  strings:
    $key_1529 = { 42 5b [2] 70 79 [2] 76 4c [2] 58 4c [2] 67 50 }

  condition:
    any of them
}