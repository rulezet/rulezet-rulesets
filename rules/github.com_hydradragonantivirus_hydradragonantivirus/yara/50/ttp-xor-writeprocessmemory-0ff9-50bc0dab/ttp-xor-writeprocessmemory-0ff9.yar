rule TTP_XOR_WriteProcessMemory_0ff9 {
  strings:
    $key_0ff9 = { 58 8b [2] 6a a9 [2] 6c 9c [2] 42 9c [2] 7d 80 }

  condition:
    any of them
}