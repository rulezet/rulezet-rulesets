rule TTP_XOR_WriteProcessMemory_1f62 {
  strings:
    $key_1f62 = { 48 10 [2] 7a 32 [2] 7c 07 [2] 52 07 [2] 6d 1b }

  condition:
    any of them
}