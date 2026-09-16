rule TTP_XOR_WriteProcessMemory_1840 {
  strings:
    $key_1840 = { 4f 32 [2] 7d 10 [2] 7b 25 [2] 55 25 [2] 6a 39 }

  condition:
    any of them
}