rule TTP_XOR_WriteProcessMemory_59f2 {
  strings:
    $key_59f2 = { 0e 80 [2] 3c a2 [2] 3a 97 [2] 14 97 [2] 2b 8b }

  condition:
    any of them
}