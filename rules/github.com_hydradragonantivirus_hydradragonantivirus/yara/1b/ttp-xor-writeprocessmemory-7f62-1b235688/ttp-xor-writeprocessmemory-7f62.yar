rule TTP_XOR_WriteProcessMemory_7f62 {
  strings:
    $key_7f62 = { 28 10 [2] 1a 32 [2] 1c 07 [2] 32 07 [2] 0d 1b }

  condition:
    any of them
}