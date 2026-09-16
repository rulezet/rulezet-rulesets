rule TTP_XOR_WriteProcessMemory_07f9 {
  strings:
    $key_07f9 = { 50 8b [2] 62 a9 [2] 64 9c [2] 4a 9c [2] 75 80 }

  condition:
    any of them
}