rule TTP_XOR_WriteProcessMemory_20f9 {
  strings:
    $key_20f9 = { 77 8b [2] 45 a9 [2] 43 9c [2] 6d 9c [2] 52 80 }

  condition:
    any of them
}