rule TTP_XOR_WriteProcessMemory_20e9 {
  strings:
    $key_20e9 = { 77 9b [2] 45 b9 [2] 43 8c [2] 6d 8c [2] 52 90 }

  condition:
    any of them
}