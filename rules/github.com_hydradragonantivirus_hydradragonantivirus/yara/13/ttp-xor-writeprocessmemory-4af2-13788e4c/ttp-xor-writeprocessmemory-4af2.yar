rule TTP_XOR_WriteProcessMemory_4af2 {
  strings:
    $key_4af2 = { 1d 80 [2] 2f a2 [2] 29 97 [2] 07 97 [2] 38 8b }

  condition:
    any of them
}