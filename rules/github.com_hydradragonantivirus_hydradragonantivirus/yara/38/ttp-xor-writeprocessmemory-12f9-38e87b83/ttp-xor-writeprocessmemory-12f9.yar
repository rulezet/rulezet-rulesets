rule TTP_XOR_WriteProcessMemory_12f9 {
  strings:
    $key_12f9 = { 45 8b [2] 77 a9 [2] 71 9c [2] 5f 9c [2] 60 80 }

  condition:
    any of them
}