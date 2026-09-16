rule TTP_XOR_WriteProcessMemory_2a62 {
  strings:
    $key_2a62 = { 7d 10 [2] 4f 32 [2] 49 07 [2] 67 07 [2] 58 1b }

  condition:
    any of them
}