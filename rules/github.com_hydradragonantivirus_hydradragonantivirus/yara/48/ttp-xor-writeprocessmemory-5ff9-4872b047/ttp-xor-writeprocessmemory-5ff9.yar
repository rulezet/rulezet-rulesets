rule TTP_XOR_WriteProcessMemory_5ff9 {
  strings:
    $key_5ff9 = { 08 8b [2] 3a a9 [2] 3c 9c [2] 12 9c [2] 2d 80 }

  condition:
    any of them
}