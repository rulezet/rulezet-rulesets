rule TTP_XOR_WriteProcessMemory_1822 {
  strings:
    $key_1822 = { 4f 50 [2] 7d 72 [2] 7b 47 [2] 55 47 [2] 6a 5b }

  condition:
    any of them
}