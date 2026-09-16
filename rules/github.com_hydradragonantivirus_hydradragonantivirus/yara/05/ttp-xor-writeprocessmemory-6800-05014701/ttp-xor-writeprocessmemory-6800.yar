rule TTP_XOR_WriteProcessMemory_6800 {
  strings:
    $key_6800 = { 3f 72 [2] 0d 50 [2] 0b 65 [2] 25 65 [2] 1a 79 }

  condition:
    any of them
}