rule TTP_XOR_WriteProcessMemory_2063 {
  strings:
    $key_2063 = { 77 11 [2] 45 33 [2] 43 06 [2] 6d 06 [2] 52 1a }

  condition:
    any of them
}