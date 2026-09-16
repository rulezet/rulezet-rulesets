rule TTP_XOR_WriteProcessMemory_3050 {
  strings:
    $key_3050 = { 67 22 [2] 55 00 [2] 53 35 [2] 7d 35 [2] 42 29 }

  condition:
    any of them
}