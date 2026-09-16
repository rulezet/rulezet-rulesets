rule TTP_XOR_WriteProcessMemory_0822 {
  strings:
    $key_0822 = { 5f 50 [2] 6d 72 [2] 6b 47 [2] 45 47 [2] 7a 5b }

  condition:
    any of them
}