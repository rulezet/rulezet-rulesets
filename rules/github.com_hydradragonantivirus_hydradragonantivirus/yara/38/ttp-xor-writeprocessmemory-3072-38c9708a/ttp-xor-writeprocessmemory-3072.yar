rule TTP_XOR_WriteProcessMemory_3072 {
  strings:
    $key_3072 = { 67 00 [2] 55 22 [2] 53 17 [2] 7d 17 [2] 42 0b }

  condition:
    any of them
}