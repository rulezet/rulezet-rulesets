rule TTP_XOR_WriteProcessMemory_2043 {
  strings:
    $key_2043 = { 77 31 [2] 45 13 [2] 43 26 [2] 6d 26 [2] 52 3a }

  condition:
    any of them
}