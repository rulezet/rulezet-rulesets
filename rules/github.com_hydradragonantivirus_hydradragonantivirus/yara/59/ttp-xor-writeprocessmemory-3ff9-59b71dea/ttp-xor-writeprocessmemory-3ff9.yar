rule TTP_XOR_WriteProcessMemory_3ff9 {
  strings:
    $key_3ff9 = { 68 8b [2] 5a a9 [2] 5c 9c [2] 72 9c [2] 4d 80 }

  condition:
    any of them
}