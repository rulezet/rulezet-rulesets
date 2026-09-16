rule TTP_XOR_WriteProcessMemory_46e9 {
  strings:
    $key_46e9 = { 11 9b [2] 23 b9 [2] 25 8c [2] 0b 8c [2] 34 90 }

  condition:
    any of them
}