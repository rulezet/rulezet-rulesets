rule TTP_XOR_WriteProcessMemory_1800 {
  strings:
    $key_1800 = { 4f 72 [2] 7d 50 [2] 7b 65 [2] 55 65 [2] 6a 79 }

  condition:
    any of them
}