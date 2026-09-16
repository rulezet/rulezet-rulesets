rule TTP_XOR_WriteProcessMemory_47e9 {
  strings:
    $key_47e9 = { 10 9b [2] 22 b9 [2] 24 8c [2] 0a 8c [2] 35 90 }

  condition:
    any of them
}