rule TTP_XOR_WriteProcessMemory_2052 {
  strings:
    $key_2052 = { 77 20 [2] 45 02 [2] 43 37 [2] 6d 37 [2] 52 2b }

  condition:
    any of them
}