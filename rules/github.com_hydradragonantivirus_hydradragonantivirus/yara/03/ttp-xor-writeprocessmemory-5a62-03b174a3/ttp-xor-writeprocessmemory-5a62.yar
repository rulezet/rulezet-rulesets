rule TTP_XOR_WriteProcessMemory_5a62 {
  strings:
    $key_5a62 = { 0d 10 [2] 3f 32 [2] 39 07 [2] 17 07 [2] 28 1b }

  condition:
    any of them
}