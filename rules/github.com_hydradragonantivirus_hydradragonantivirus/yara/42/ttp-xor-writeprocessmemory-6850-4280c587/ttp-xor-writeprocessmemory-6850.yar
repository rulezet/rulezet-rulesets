rule TTP_XOR_WriteProcessMemory_6850 {
  strings:
    $key_6850 = { 3f 22 [2] 0d 00 [2] 0b 35 [2] 25 35 [2] 1a 29 }

  condition:
    any of them
}