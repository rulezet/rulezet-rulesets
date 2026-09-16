rule TTP_XOR_WriteProcessMemory_2050 {
  strings:
    $key_2050 = { 77 22 [2] 45 00 [2] 43 35 [2] 6d 35 [2] 52 29 }

  condition:
    any of them
}