rule TTP_XOR_WriteProcessMemory_3862 {
  strings:
    $key_3862 = { 6f 10 [2] 5d 32 [2] 5b 07 [2] 75 07 [2] 4a 1b }

  condition:
    any of them
}