rule TTP_XOR_WriteProcessMemory_3850 {
  strings:
    $key_3850 = { 6f 22 [2] 5d 00 [2] 5b 35 [2] 75 35 [2] 4a 29 }

  condition:
    any of them
}