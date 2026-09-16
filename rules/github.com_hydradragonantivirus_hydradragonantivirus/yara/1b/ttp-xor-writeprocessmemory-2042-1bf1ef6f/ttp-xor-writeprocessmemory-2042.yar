rule TTP_XOR_WriteProcessMemory_2042 {
  strings:
    $key_2042 = { 77 30 [2] 45 12 [2] 43 27 [2] 6d 27 [2] 52 3b }

  condition:
    any of them
}