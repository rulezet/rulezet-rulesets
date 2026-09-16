rule TTP_XOR_WriteProcessMemory_2850 {
  strings:
    $key_2850 = { 7f 22 [2] 4d 00 [2] 4b 35 [2] 65 35 [2] 5a 29 }

  condition:
    any of them
}