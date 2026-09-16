rule TTP_XOR_WriteProcessMemory_3012 {
  strings:
    $key_3012 = { 67 60 [2] 55 42 [2] 53 77 [2] 7d 77 [2] 42 6b }

  condition:
    any of them
}